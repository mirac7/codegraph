from requests import get
from core.interface import GraphBuilder

for page in range(1000):
    url = f"https://api.github.com/search/repositories?q=stars:>1000%20language:Python&page={page+1}"
    for index, repo in enumerate(get(url).json()["items"], start=1):
        for status in GraphBuilder(repo["html_url"]).stream_process_repository():
            print(page*30+index, repo["html_url"], status)
