from typing import Callable


def confirm_action(action: str) -> bool:
    """
    Request explicit user confirmation before executing
    a sensitive write operation.
    """

    while True:
        answer = input(
            f"\nConfirmation required.\n"
            f"Do you want to {action}? (yes/no): "
        ).strip().lower()

        if answer in ("yes", "y"):
            return True

        if answer in ("no", "n"):
            return False

        print("Please enter 'yes' or 'no'.")