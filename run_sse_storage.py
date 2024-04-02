import argparse
import pyfiledrop
import subprocess
import sys


def parse_args():
    parser = argparse.ArgumentParser()
    # parser.add_argument("--dz-version", type=str, default=None, required=False)
    return parser.parse_args()

def main():
    subprocess.run([sys.executable, "pyfiledrop.py", "-a"])

if __name__ == "__main__":
    main()
