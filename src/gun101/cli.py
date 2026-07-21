"""Command-line interface for GUN-101."""
import argparse
import sys
import os
from . import handler
from . import keyfile

def encrypt(args):
    """Handle the encrypt subcommand."""
    try:
        with open(args.file, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        container = handler.encrypt_file(data, args.password, args.keyfile)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output if args.output else (args.file + '.gun101')
    try:
        with open(output_path, 'wb') as f:
            f.write(container)
    except OSError as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Encrypted file written to: {output_path}")

def decrypt(args):
    """Handle the decrypt subcommand."""
    try:
        with open(args.file, 'rb') as f:
            container = f.read()
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        data = handler.decrypt_file(container, args.password, args.keyfile)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output
    if output_path is None:
        # Default: strip .gun101 extension or append .decrypted
        if args.file.endswith('.gun101'):
            output_path = args.file[:-7]  # remove .gun101
        else:
            output_path = args.file + '.decrypted'

    try:
        with open(output_path, 'wb') as f:
            f.write(data)
    except OSError as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Decrypted file written to: {output_path}")

def generate_keyfile(args):
    """Handle the generate-keyfile subcommand."""
    try:
        keyfile.generate_keyfile(args.path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error creating keyfile: {e}", file=sys.stderr)
        sys.exit(1)

    # Print fingerprint for user to record
    try:
        with open(args.path, 'rb') as f:
            data = f.read()
        fingerprint = keyfile.keyfile_fingerprint(data)
        print(f"Keyfile generated at: {args.path}")
        print(f"Fingerprint (SHA-256): {fingerprint}")
    except OSError as e:
        print(f"Error reading back keyfile for fingerprint: {e}", file=sys.stderr)
        sys.exit(1)

def keyfile_fingerprint(args):
    """Handle the keyfile-fingerprint subcommand."""
    try:
        with open(args.path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(f"Error reading keyfile: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        fingerprint = keyfile.keyfile_fingerprint(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Fingerprint (SHA-256): {fingerprint}")

def main():
    parser = argparse.ArgumentParser(
        description="GUN-101: A simple, secure file encryption tool using "
                    "AES-256-GCM and Argon2id."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('--keyfile', help='Path to keyfile for two-factor protection')
    encrypt_parser.add_argument('--output', help='Output file path (default: input.gun101)')
    encrypt_parser.add_argument('--password', required=True, help='Password for encryption')
    encrypt_parser.set_defaults(func=encrypt)

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--keyfile', help='Path to keyfile for two-factor protection')
    decrypt_parser.add_argument('--output', help='Output file path (default: strip .gun101 or add .decrypted)')
    decrypt_parser.add_argument('--password', required=True, help='Password for decryption')
    decrypt_parser.set_defaults(func=decrypt)

    # Generate-keyfile subcommand
    gen_key_parser = subparsers.add_parser('generate-keyfile', help='Generate a new keyfile')
    gen_key_parser.add_argument('path', help='Path where the keyfile will be created')
    gen_key_parser.set_defaults(func=generate_keyfile)

    # Keyfile-fingerprint subcommand
    fp_parser = subparsers.add_parser('keyfile-fingerprint', help='Show fingerprint of an existing keyfile')
    fp_parser.add_argument('path', help='Path to the keyfile')
    fp_parser.set_defaults(func=keyfile_fingerprint)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()