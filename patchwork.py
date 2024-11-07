from github import Github

import os
import re
import requests

PW_BASE_URL = "https://patchwork.kernel.org/api/1.1"

def requests_url(url: str):
    """ Helper function to requests WEB API GET with URL """

    resp = requests.get(url)
    if resp.status_code != 200:
        raise requests.HTTPError("GET {}".format(resp.status_code))

    return resp

def requests_post(url: str, headers: dict, content: dict):
    """ Helper function to post data to URL """

    resp = requests.post(url, content, headers=headers)
    if resp.status_code != 201:
        raise requests.HTTPError("POST {}".format(resp.status_code))

    return resp

def get_sid(pr_title: str):
    """
    Parse PR title prefix and get PatchWork Series ID
    PR Title Prefix = "[PW_S_ID:<series_id>] XXXXX"
    """

    try:
        sid = re.search(r'^\[PW_SID:([0-9]+)\]', pr_title).group(1)
    except AttributeError:
        print("Unable to find the series_id from title %s" % pr_title)
        sid = None

    return sid

def get_series(sid: str):
	""" Get series detail from patchwork """

	url = PW_BASE_URL + "/series/" + sid
	req = requests_url(url)

	return req.json()

def get_patch(id: int):
	""" Get patch from patchwork """

	url = PW_BASE_URL + "/patches/%d" % id
	req = requests_url(url)

	return Patch(req.json())

class Patch(dict):
	def __init__(self,*args,**kwargs):
		super(Patch, self).__init__(*args, **kwargs)

	def save(self):
		""" Save patch to file and return the file path """

		filename = os.path.join('/tmp/', str(self['id']) + ".patch")

		patch_mbox = requests_url(self["mbox"])

		with open(filename, "wb") as file:
			file.write(patch_mbox.content)

		self._saved_patch = filename

		return filename

	def save_msg(self):
		""" Save patch commit message to file and return the path """

		filename = os.path.join('/tmp/', str(self['id']) + '.msg')

		with open(filename, "wb") as file:
			file.write(bytes(self['name'], 'utf-8'))
			file.write(b"\n\n")
			file.write(bytes(self['content'], 'utf-8'))

		self._saved_msg = filename

		return filename

	def __del__(self):
		if hasattr(self, '_saved_patch'):
			os.remove(self._saved_patch)

		if hasattr(self, '_saved_msg'):
			os.remove(self._saved_msg)

class Patchwork:
	'''
		This class handles retrieving patches from patchwork and posting
		results. The Patchwork series is initialized with a user ID,
		github repository ('owner/repo') and a PR number.

		The tokens are obtained from the environment unless provided.
	'''
	def __init__(self, user: int, repo: str, pr: int,
			pw_token: str = os.environ.get('PATCHWORK_TOKEN', None),
			gh_token: str = os.environ.get('GITHUB_TOKEN', None)):
		gh_repo = Github(gh_token).get_repo(repo)
		self.gh_pr = gh_repo.get_pull(pr)
		sid = get_sid(self.gh_pr.title)

		if not sid:
			raise Exception("Unable to find series ID")

		self.series = get_series(sid)

		print(self.series)
		self.pw_token = pw_token
		self.user = user
		self.patches = [get_patch(p['id']) for p in self.series['patches']]

	def __iter__(self):
		self.idx = 0
		return iter(self.patches)

	def __next__(self):
		self.idx += 1
		return self.patches[self.idx]

	def __getitem__(self, item):
		return self.patches[item]

	def __len__(self):
		return len(self.patches)

	def post_result(self, patch: Patch, status: int, name: str,
			message: str):
		headers = {
			'Authorization': f'Token {self.pw_token}'
		}

		content = {
			'user': self.user,
			'state': status,
			'target_url': self.gh_pr.html_url,
			'context': name,
			'description': message
		}

		req = requests_post(patch['checks'], headers, content)

		return req.json()


