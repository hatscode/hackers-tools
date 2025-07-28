
"""
    We use pip to install different packages which we can import in our program
    PIP stands for predifined installer program
    We write the commands in a terminal to install the packages

    pip install pip - to install the pip manager
    pip --version

"""

import webbrowser # web browser module to open websites

# list of urls: python
url_lists = [
    'http://www.python.org',
    'https://www.linkedin.com/in/iam4lex/',
    'https://github.com/iam4lex',
    'https://twitter.com/iam4lex'
]

print(url_lists[0])

webbrowser.open_new_tab(url_lists[0])

# opens the above list of websites in a different tab
# for url in url_lists:
#     webbrowser.open_new_tab(url)