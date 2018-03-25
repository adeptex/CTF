import requests 

class Curl():
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Firefox',
            'Referer': 'https://google.com'
        })

    def get(self, **kwargs):
        return self.session.get(kwargs)

    def post(self, **kwargs):
        return self.session.post(kwargs)
