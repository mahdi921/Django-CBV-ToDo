import threading


class EmailThread(threading.Thread):
    """This class is used to send email in a separate thread."""

    def __init__(self, email_obj):
        """init method is used to initialize the email object."""
        self.email_obj = email_obj
        threading.Thread.__init__(self)

    def run(self):
        """This method is used to run the thread."""
        self.email_obj.send()
