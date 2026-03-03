import os
import pwd


def has_required_privileges(is_setup_mode: bool = False) -> bool:
    """
    Checks if the current process has the necessary permissions.
    - Setup Mode: STRICTLY requires root (EUID 0) to write to /etc.
    - Live Mode: Requires root OR the dedicated 'ddos-martummai' system user
                 (which receives network capabilities from systemd).
    """
    try:
        euid = os.geteuid()

        # Root (sudo) is always fully privileged
        if euid == 0:
            return True

        # If running in Live mode, allow our dedicated system user to pass
        if not is_setup_mode:
            try:
                # Resolve the username from the EUID
                user_name = pwd.getpwuid(euid).pw_name
                if user_name == "ddos-martummai":
                    return True
            except KeyError:
                pass  # UID not found in /etc/passwd

        return False
    except AttributeError:
        # Bypass Windows check
        return True
