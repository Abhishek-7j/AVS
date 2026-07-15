"""
Authenticated Security Audit module for AVS.
Verifies configurations and credentials for SSH and Databases.
"""
from __future__ import annotations

import os
from plugins import Finding

# Global helper to load local environment file
def load_env() -> None:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'").strip('"')
                    os.environ.setdefault(k, v)

# Run environment loader on module load
load_env()


def run_authenticated_checks(host: str, open_ports: list[tuple]) -> list[Finding]:
    findings: list[Finding] = []

    for port, service, _ in open_ports:
        s = (service or "").lower()
        # SSH Checks
        if port == 22 or s == "ssh":
            findings.extend(check_ssh_auth(host, port))

        # MySQL Checks
        if port == 3306 or "mysql" in s:
            findings.extend(check_mysql_auth(host, port))

    return findings


def check_ssh_auth(host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    user = os.environ.get("AVS_SSH_USER")
    password = os.environ.get("AVS_SSH_PASS")
    key_path = os.environ.get("AVS_SSH_KEY")

    if not user:
        return findings

    try:
        import paramiko
    except ImportError:
        findings.append(
            Finding(
                plugin_id="AVS-AUTH-SSH-MISSING-DEP",
                name="SSH Auth Audit skipped",
                severity="Info",
                cvss=0.0,
                port=port,
                service="ssh",
                description="SSH credentials provided but 'paramiko' package is not installed.",
                solution="Install paramiko using 'pip install paramiko' to enable authenticated SSH auditing.",
                refs=[]
            )
        )
        return findings

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connected = False
    try:
        if key_path and os.path.exists(key_path):
            ssh.connect(host, port=port, username=user, key_filename=key_path, timeout=5)
            connected = True
        elif password:
            ssh.connect(host, port=port, username=user, password=password, timeout=5)
            connected = True
    except Exception:
        pass

    if connected:
        findings.append(
            Finding(
                plugin_id="AVS-AUTH-SSH-SUCCESS",
                name="SSH Authenticated login successful",
                severity="Info",
                cvss=0.0,
                port=port,
                service="ssh",
                description=f"Logged in successfully via SSH using user: '{user}'. Performing system configuration audit.",
                solution="Secure SSH credentials and restrict logins to necessary users only.",
                refs=[]
            )
        )
        try:
            stdin, stdout, stderr = ssh.exec_command("uname -a", timeout=3)
            uname = stdout.read().decode(errors="ignore").strip()
            if uname:
                findings.append(
                    Finding(
                        plugin_id="AVS-AUTH-SSH-UNAME",
                        name="SSH Audit: Host OS information gathered",
                        severity="Info",
                        cvss=0.0,
                        port=port,
                        service="ssh",
                        description=f"Gathered system info via authenticated shell: {uname}",
                        solution="Ensure the kernel version is patched against known local privilege escalation vulnerabilities.",
                        refs=[]
                    )
                )

            stdin, stdout, stderr = ssh.exec_command("grep -i '^PermitRootLogin' /etc/ssh/sshd_config", timeout=3)
            root_login = stdout.read().decode(errors="ignore").strip()
            if root_login:
                if "yes" in root_login.lower():
                    findings.append(
                        Finding(
                            plugin_id="AVS-AUTH-SSH-ROOT",
                            name="SSH Audit: Root login permitted",
                            severity="Medium",
                            cvss=5.0,
                            port=port,
                            service="ssh",
                            description=f"SSH config allows root login: '{root_login}'",
                            solution="Disable PermitRootLogin in /etc/ssh/sshd_config (set to 'no' or 'prohibit-password').",
                            refs=["https://www.ssh.com/academy/ssh/sshd_config"]
                        )
                    )

            stdin, stdout, stderr = ssh.exec_command("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config", timeout=3)
            pass_auth = stdout.read().decode(errors="ignore").strip()
            if pass_auth:
                if "yes" in pass_auth.lower():
                    findings.append(
                        Finding(
                            plugin_id="AVS-AUTH-SSH-PW-AUTH",
                            name="SSH Audit: Password authentication enabled",
                            severity="Low",
                            cvss=3.0,
                            port=port,
                            service="ssh",
                            description="SSH config allows password-based authentication.",
                            solution="Set PasswordAuthentication to 'no' in sshd_config and enforce public key authentication.",
                            refs=[]
                        )
                    )
        except Exception:
            pass
        finally:
            ssh.close()

    return findings


def check_mysql_auth(host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    user = os.environ.get("AVS_MYSQL_USER")
    password = os.environ.get("AVS_MYSQL_PASS")

    if not user:
        return findings

    try:
        import pymysql
    except ImportError:
        findings.append(
            Finding(
                plugin_id="AVS-AUTH-DB-MISSING-DEP",
                name="MySQL Auth Audit skipped",
                severity="Info",
                cvss=0.0,
                port=port,
                service="mysql",
                description="MySQL credentials provided but 'pymysql' package is not installed.",
                solution="Install pymysql using 'pip install pymysql' to enable database auditing.",
                refs=[]
            )
        )
        return findings

    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            connect_timeout=4
        )
        findings.append(
            Finding(
                plugin_id="AVS-AUTH-MYSQL-SUCCESS",
                name="MySQL Authenticated login successful",
                severity="Info",
                cvss=0.0,
                port=port,
                service="mysql",
                description=f"Database login succeeded using user: '{user}'. Performing configuration audit.",
                solution="Restrict database administrative permissions to trusted accounts and IPs only.",
                refs=[]
            )
        )
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                db_ver = cursor.fetchone()
                if db_ver:
                    findings.append(
                        Finding(
                            plugin_id="AVS-AUTH-MYSQL-VERSION",
                            name="MySQL Audit: Database version gathered",
                            severity="Info",
                            cvss=0.0,
                            port=port,
                            service="mysql",
                            description=f"MySQL Server Version: {db_ver[0]}",
                            solution="Verify version details and ensure all patches are applied.",
                            refs=[]
                        )
                    )
                cursor.execute("SELECT User, Host FROM mysql.user WHERE Password='' or authentication_string=''")
                empty_users = cursor.fetchall()
                if empty_users:
                    users_list = ", ".join(f"'{u[0]}'@'{u[1]}'" for u in empty_users)
                    findings.append(
                        Finding(
                            plugin_id="AVS-AUTH-MYSQL-EMPTY-PW",
                            name="MySQL Audit: Accounts with empty password",
                            severity="High",
                            cvss=8.0,
                            port=port,
                            service="mysql",
                            description=f"Accounts with empty password: {users_list}",
                            solution="Assign strong passwords to all database users.",
                            refs=["CWE-258"]
                        )
                    )
        except Exception:
            pass
        finally:
            conn.close()
    except Exception:
        pass

    return findings
