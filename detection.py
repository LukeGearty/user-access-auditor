
"""
Building detection rules as its own function

"""
import pandas as pd


def find_dormant_accounts(df, days: int = 90) -> pd.DataFrame:
    """
    Find users whose last login exceeds the dormancy threshold - default is 90 days

    If users have not logged in, this function will find them and flag them

    90 days is a common industry threshold used in SOC 2 and ISO 27001 access reviews.
    
    """
    today = pd.Timestamp.today()    
    last_logins = pd.to_datetime(df["last_login_date"])
    delta = (today - last_logins).dt.days
    dormant_mask = delta > days
    ghost_mask = last_logins.isna()
    combined_mask = dormant_mask | ghost_mask

    flagged = df[combined_mask].copy()
    flagged["risk_reason"] = flagged["last_login_date"].apply(
        lambda x: "Ghost account: never logged in" if pd.isna(x)
        else f"Dormant account: no login in over {days} days"
    )
    return flagged


        

def find_inactive_contractors(df) -> pd.DataFrame:
    
    """
    
    Flags contractors whose contract_end_date has passed but still have active accounts
    
    """
    today = pd.Timestamp.today()
    contractors = df[df["employment_type"] == "contractor"].copy()
    end_dates = pd.to_datetime(contractors["contract_end_date"])
    expired_mask = end_dates < today
    active_mask = contractors["account_status"] == "active"

    flagged = contractors[expired_mask & active_mask].copy()
    flagged["risk_reason"] = "Contractor access not revoked after contract expiry"
    return flagged


def find_privileged_accounts(df) -> pd.DataFrame:
    """
    Flag all accounts with elevated or admin level access.

    These accounts require regular review due to their high-value target status 
    
    """
    
    privileged_levels = ["elevated", "admin"]

    privileged_mask = df["access_level"].isin(privileged_levels)
    flagged = df[privileged_mask].copy()

    flagged["risk_reason"] = flagged["access_level"].apply(
        lambda x: "Admin account: highest privilege level, requires immediate review"
        if x == "admin"
        else "Elevated account: above standard access, requires periodic review"
    )
    return flagged


def find_disabled_with_access(df) -> pd.DataFrame:
    
    """
    Flag accounts that are disabled or suspended but still have permissions assigned.
    Permissions should be revoked at the time of deactivation. 
    """
        
    inactive_statuses = ['disabled', 'suspended']
    inactive_mask = df["account_status"].isin(inactive_statuses)

    has_permission_mask = (
        # not null and not an empty string
        (df["permissions"].notna()) & (df["permissions"].str.strip() != "")
    )

    flagged = df[inactive_mask & has_permission_mask].copy()

    flagged["risk_reason"] = flagged["account_status"].apply(
        lambda x: "Disabled account retains active permissions - access not fully revoked"
        if x == "disabled"
        else "Suspended account retains active permissions - requires immediate review"
    )
    return flagged

def find_permission_creep(df, threshold: int = 5) -> pd.DataFrame:
    """
    Flag standard users whose permission count exceeds the threshold (default: 5).
    Permission creep occurs when access accumulates over time without regular review,
    violating the principle of least privilege.
    
    """
    
    permission_count = df["permissions"].apply(
        lambda x: len(x.split("|")) if pd.notna(x) and x.strip() != "" else 0
    )

    permission_creep_mask = permission_count > threshold
    standard_mask = df["access_level"] == "standard"

    flagged = df[permission_creep_mask & standard_mask].copy()

    flagged["permission_count"] = permission_count[flagged.index]
    flagged["risk_reason"] = flagged["permission_count"].apply(
        lambda x: f"Permission creep detected: {x} permissions assigned, exceeds threshold of {threshold}"
    )

    return flagged