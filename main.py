from generate_data import generate_dataset
from detection import calculate_risk_reasons
import pandas as pd
from jinja2 import Template
from datetime import datetime



REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Review Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            font-size: 14px;
            color: #1a1a1a;
            background: #f4f6f8;
            margin: 0;
            padding: 24px;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 6px;
            padding: 32px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.1);
        }

        .header {
            border-bottom: 2px solid #d0d5dd;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }

        .header h1 {
            margin: 0 0 4px 0;
            font-size: 22px;
            color: #111827;
        }

        .header .meta {
            color: #6b7280;
            font-size: 13px;
        }

        .summary-bar {
            display: flex;
            gap: 16px;
            margin-bottom: 32px;
        }

        .summary-card {
            flex: 1;
            padding: 16px;
            border-radius: 6px;
            text-align: center;
            border: 1px solid #e5e7eb;
        }

        .summary-card .count {
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 4px;
        }

        .summary-card .label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #6b7280;
        }

        .card-total    { background: #f9fafb; }
        .card-critical { background: #fef2f2; border-color: #fca5a5; }
        .card-high     { background: #fff7ed; border-color: #fdba74; }
        .card-medium   { background: #fefce8; border-color: #fde047; }
        .card-low      { background: #f0fdf4; border-color: #86efac; }

        .card-critical .count { color: #dc2626; }
        .card-high     .count { color: #ea580c; }
        .card-medium   .count { color: #ca8a04; }
        .card-low      .count { color: #16a34a; }

        .tier-section {
            margin-bottom: 32px;
        }

        .tier-heading {
            font-size: 15px;
            font-weight: bold;
            padding: 8px 12px;
            border-radius: 4px;
            margin-bottom: 12px;
        }

        .tier-Critical { background: #fef2f2; color: #dc2626; border-left: 4px solid #dc2626; }
        .tier-High     { background: #fff7ed; color: #ea580c; border-left: 4px solid #ea580c; }
        .tier-Medium   { background: #fefce8; color: #ca8a04; border-left: 4px solid #ca8a04; }
        .tier-Low      { background: #f0fdf4; color: #16a34a; border-left: 4px solid #16a34a; }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            background: #f3f4f6;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid #e5e7eb;
            color: #374151;
            font-weight: 600;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background: #f9fafb;
        }

        .risk-reasons {
            color: #4b5563;
            font-size: 12px;
        }

        .score-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 12px;
        }

        .badge-Critical { background: #fef2f2; color: #dc2626; }
        .badge-High     { background: #fff7ed; color: #ea580c; }
        .badge-Medium   { background: #fefce8; color: #ca8a04; }
        .badge-Low      { background: #f0fdf4; color: #16a34a; }

        .footer {
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #e5e7eb;
            font-size: 12px;
            color: #9ca3af;
            text-align: center;
        }
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>{{ company_name }} — Quarterly Access Review Report</h1>
        <div class="meta">
            Generated: {{ generated_date }} &nbsp;|&nbsp;
            Total Users Reviewed: {{ total_users }} &nbsp;|&nbsp;
            Flagged Accounts: {{ total_flagged }}
        </div>
    </div>

    <div class="summary-bar">
        <div class="summary-card card-total">
            <div class="count">{{ total_flagged }}</div>
            <div class="label">Total Flagged</div>
        </div>
        <div class="summary-card card-critical">
            <div class="count">{{ counts.Critical }}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card card-high">
            <div class="count">{{ counts.High }}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card card-medium">
            <div class="count">{{ counts.Medium }}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card card-low">
            <div class="count">{{ counts.Low }}</div>
            <div class="label">Low</div>
        </div>
    </div>

    {% for tier in ["Critical", "High", "Medium", "Low"] %}
    {% if tier_groups[tier] %}
    <div class="tier-section">
        <div class="tier-heading tier-{{ tier }}">
            {{ tier }} Risk — {{ tier_groups[tier] | length }} account(s)
        </div>
        <table>
            <thead>
                <tr>
                    <th>User ID</th>
                    <th>Name</th>
                    <th>Department</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Access Level</th>
                    <th>Last Login</th>
                    <th>Score</th>
                    <th>Risk Reasons</th>
                </tr>
            </thead>
            <tbody>
                {% for row in tier_groups[tier] %}
                <tr>
                    <td>{{ row.user_id }}</td>
                    <td>{{ row.full_name }}</td>
                    <td>{{ row.department }}</td>
                    <td>{{ row.employment_type }}</td>
                    <td>{{ row.account_status }}</td>
                    <td>{{ row.access_level }}</td>
                    <td>{{ row.last_login_date if row.last_login_date else "Never" }}</td>
                    <td>
                        <span class="score-badge badge-{{ row.severity_tier }}">
                            {{ row.risk_score }}
                        </span>
                    </td>
                    <td class="risk-reasons">{{ row.risk_reasons }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    {% endfor %}

    <div class="footer">
        This report is auto-generated by the Access Review Automation Tool.
        Review findings with the IAM team before taking remediation action.
    </div>

</div>
</body>
</html>
"""


def export_html_report(df: pd.DataFrame, findings_df: pd.DataFrame):
    tier_order = ["Critical", "High", "Medium", "Low"]

    tier_groups = {tier: [] for tier in tier_order}

    for _, row in findings_df.iterrows():
        tier = row.get("severity_tier", "Low")
        if tier in tier_groups:
            tier_groups[tier].append(row)
    
    for tier in tier_order:
        tier_groups[tier].sort(key=lambda r: r["risk_score"], reverse=True)
    
    counts = {tier: len(tier_groups[tier]) for tier in tier_order}

    template = Template(REPORT_TEMPLATE)
    
    html = template.render(
        company_name="Acme Group",
        generated_date=datetime.today().strftime("%B %d, %Y at %I:%M %p"),
        total_users=len(df),
        total_flagged=len(findings_df),
        counts=counts,
        tier_groups=tier_groups,
    )

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)



def main():
    print("Loading Dataset...")
    df = generate_dataset()
    print("Running detection functions...")
    findings = calculate_risk_reasons(df)

    print("Generating outputs...")
    findings.to_csv("risk_findings.csv", index=False)
    export_html_report(df, findings)


if __name__=="__main__":
    main()