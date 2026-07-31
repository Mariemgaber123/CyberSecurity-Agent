import time


def show_progress(task_name: str):
    """
    Simulate a long-running task by reporting progress.
    This can later be replaced with real MCP progress notifications.
    """

    steps = [0, 20, 40, 60, 80, 100]

    for percent in steps:
        print(f"[PROGRESS] {task_name}: {percent}%")
        time.sleep(0.5)

    print(f"[DONE] {task_name}")