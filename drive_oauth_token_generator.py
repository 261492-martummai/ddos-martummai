# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "google-auth-oauthlib",
# ]
# ///

import argparse
import sys
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://www.googleapis.com/auth/drive.file"]


def main(client_secrets_file):
    secret_path = Path(client_secrets_file).resolve()

    if not secret_path.is_file():
        print(f"File '{secret_path}' not found")
        sys.exit(1)

    flow = InstalledAppFlow.from_client_secrets_file(str(secret_path), SCOPES)

    creds = flow.run_local_server(port=0)

    output_filename = "google-drive-token.json"
    with open(output_filename, "w") as token:
        token.write(creds.to_json())

    print(f"Success! '{output_filename}' has been created.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Google Drive OAuth Token")

    parser.add_argument(
        "client_secret", type=Path, help="Path to the client_secrets_file JSON"
    )

    args = parser.parse_args()

    main(args.client_secret)
