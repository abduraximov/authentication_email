from django.core.mail import send_mail
import threading
import re

def send_email(to_email, subject, message):
    from_email = 'abdurakhimovy@gmail.com'
    send_mail(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=[to_email],
        fail_silently=False,
    )

def send_confirmation_code(to_email, code):
    
    # Send the SMS and email in parallel using threads
    email_thread = threading.Thread(target=send_email, args=(to_email, 'Confirmation Code', f'Your confirmation code is {code}'))
    email_thread.start()

    # Wait for both threads to finish
    email_thread.join()

def email_checkss(email):
    email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
    if re.fullmatch(email_regex, email):
        email = "email"
    else:
        email = "Error, it is not email"
    return email