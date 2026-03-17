from faker import Faker
import pandas as pd
import random
from datetime import datetime, timedelta

fake = Faker()
Faker.seed(42)
random.seed(42)

DEPARTMENTS = ["IT", "Finance", "HR", "Engineering", "Sales", "Legal", "Operations"]

TITLES_BY_DEPT = {
    "IT":          ["Systems Administrator", "Help Desk Analyst", "Network Engineer", "IAM Analyst", "Security Analyst"],
    "Finance":     ["Financial Analyst", "Accounts Payable Specialist", "Controller", "Budget Analyst"],
    "HR":          ["HR Generalist", "Recruiter", "HR Director", "Compensation Analyst"],
    "Engineering": ["Software Engineer", "DevOps Engineer", "QA Analyst", "Site Reliability Engineer"],
    "Sales":       ["Account Executive", "Sales Manager", "Business Development Rep", "Sales Operations Analyst"],
    "Legal":       ["Legal Counsel", "Compliance Analyst", "Paralegal"],
    "Operations":  ["Operations Manager", "Business Analyst", "Project Coordinator", "Process Improvement Analyst"],
}

PERMISSION_POOL = [
    "VPN_Access",
    "Active_Directory",
    "GitHub_Repo",
    "AWS_Console",
    "Salesforce",
    "SAP_Finance",
    "Workday_HR",
    "Jira",
    "Confluence",
    "Okta_Admin",
    "Azure_Portal",
    "PCI_Data_Access",
    "HIPAA_Records",
    "Payroll_System",
    "IT_Admin_Console",
]

STANDARD_PERMS   = ["VPN_Access", "Active_Directory", "Jira", "Confluence", "Salesforce"]
ELEVATED_PERMS   = STANDARD_PERMS + ["GitHub_Repo", "AWS_Console", "Workday_HR", "SAP_Finance"]
ADMIN_PERMS      = PERMISSION_POOL  

def random_date(start_days_ago: int, end_days_ago: int) -> str:
    """Return a random date string between two day offsets from today."""
    days = random.randint(end_days_ago, start_days_ago)
    return (datetime.today() - timedelta(days=days)).strftime("%Y-%m-%d")


def pick_permissions(access_level: str, count: int = None) -> str:
    """Return a pipe-separated permission string appropriate for the access level."""
    if access_level == "standard":
        pool = STANDARD_PERMS
        count = count or random.randint(2, 4)
    elif access_level == "elevated":
        pool = ELEVATED_PERMS
        count = count or random.randint(4, 6)
    else:  # admin
        pool = ADMIN_PERMS
        count = count or random.randint(6, 10)

    count = min(count, len(pool))
    return "|".join(random.sample(pool, count))


def build_user(user_id: int, employment_type: str = "employee", edge_case: str = None) -> dict:
    """
    Build a single user record.

    Edge case values:
        "dormant"                 - active account, no login in 90-365 days
        "disabled_with_access"    - disabled account still holding permissions
        "contractor_overstay"     - contractor whose contract_end_date has passed
        "admin_outside_it"        - admin privileges granted to a non-IT employee
        "permission_creep"        - standard user with far too many permissions
        "dormant_admin"           - admin account that is also dormant (high severity)
        "suspended_elevated"      - suspended account still holding elevated/admin rights
        "mfa_disabled_admin"      - admin account with MFA turned off
        "contractor_admin"        - contractor with admin-level access
        "ghost_account"           - account that has never logged in
    """

    dept         = random.choice(DEPARTMENTS)
    title        = random.choice(TITLES_BY_DEPT[dept])
    access_level = "standard"
    status       = "active"
    last_login   = random_date(30, 1)
    hire_date    = random_date(1825, 180)
    contract_end = None
    mfa_enabled  = True
    risk_notes   = ""
    permissions  = pick_permissions("standard")

    if employment_type == "contractor":
        contract_end = random_date(-30, -180)  
    if edge_case == "dormant":
        last_login   = random_date(365, 91)
        risk_notes   = "Account dormant; no login in over 90 days"

    elif edge_case == "disabled_with_access":
        status       = "disabled"
        permissions  = pick_permissions("standard", count=random.randint(2, 5))
        last_login   = random_date(365, 90)
        risk_notes   = "Account disabled but permissions not revoked"

    elif edge_case == "contractor_overstay":
        employment_type = "contractor"
        contract_end    = random_date(365, 30) 
        risk_notes      = "Contractor contract expired; access not revoked"

    elif edge_case == "admin_outside_it":
        dept         = random.choice(["Finance", "HR", "Sales", "Legal", "Operations"])
        title        = random.choice(TITLES_BY_DEPT[dept])
        access_level = "admin"
        permissions  = pick_permissions("admin")
        risk_notes   = "Admin privileges assigned outside of IT department"

    elif edge_case == "permission_creep":
        permissions  = "|".join(random.sample(PERMISSION_POOL, random.randint(8, 12)))
        risk_notes   = "Standard user has accumulated excessive permissions"

    elif edge_case == "dormant_admin":
        access_level = "admin"
        permissions  = pick_permissions("admin")
        last_login   = random_date(365, 91)
        risk_notes   = "Admin account dormant; high severity risk"

    elif edge_case == "suspended_elevated":
        status       = "suspended"
        access_level = random.choice(["elevated", "admin"])
        permissions  = pick_permissions(access_level)
        risk_notes   = "Suspended account retains elevated or admin rights"

    elif edge_case == "mfa_disabled_admin":
        access_level = "admin"
        permissions  = pick_permissions("admin")
        mfa_enabled  = False
        risk_notes   = "Admin account does not have MFA enabled"

    elif edge_case == "contractor_admin":
        employment_type = "contractor"
        contract_end    = random_date(-30, -180) 
        access_level    = "admin"
        permissions     = pick_permissions("admin")
        risk_notes      = "Contractor account holds admin-level access"

    elif edge_case == "ghost_account":
        last_login   = None
        risk_notes   = "Account has never logged in since creation"


    # TODO: Add better full_name, email and manager to bring consistency across the dataset
    return {
        "user_id":           f"U{str(user_id).zfill(3)}",
        "full_name":         fake.name(),
        "email":             fake.company_email(),
        "department":        dept,
        "job_title":         title,
        "employment_type":   employment_type,
        "account_status":    status,
        "access_level":      access_level,
        "permissions":       permissions,
        "last_login_date":   last_login,
        "hire_date":         hire_date,
        "contract_end_date": contract_end,
        "manager":           fake.name(),
        "mfa_enabled":       mfa_enabled,
        "risk_notes":        risk_notes,
    }

def generate_dataset() -> pd.DataFrame:
    """
    Assemble 100 user records according to the target distribution:

        45  — clean active employees
        10  — clean active contractors
        12  — dormant accounts
         8  — disabled accounts with lingering access
         7  — contractors past their end date
         4  — admin accounts outside IT
         6  — permission creep cases
         8  — high-severity combinations
        ───
        100   total
    """

    records = []
    uid = 1 

    def add(n, **kwargs):
        nonlocal uid
        for _ in range(n):
            records.append(build_user(uid, **kwargs))
            uid += 1

    add(45, employment_type="employee")
    add(10, employment_type="contractor")

    add(12, edge_case="dormant")
    add(8,  edge_case="disabled_with_access")
    add(7,  edge_case="contractor_overstay")
    add(4,  edge_case="admin_outside_it")
    add(6,  edge_case="permission_creep")

    add(2, edge_case="dormant_admin")
    add(2, edge_case="suspended_elevated")
    add(2, edge_case="mfa_disabled_admin")
    add(1, edge_case="contractor_admin")
    add(1, edge_case="ghost_account")

    df = pd.DataFrame(records)

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv("user_access_data.csv", index=False)
    return df