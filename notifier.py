from plyer import notification

def notify(title: str, message: str):
    notification.notify(
        title=title,
        message=message,
        timeout=6
    )