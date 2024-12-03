import hashlib

def generate_issue_hash(issue_type, file_path, line_number, code_snippet):
    """
    Generates a SHA-256 hash for an issue based on its type, file path, line number, and code snippet.
    """
    hash_input = f"{issue_type}|{file_path}|{line_number}|{code_snippet}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
