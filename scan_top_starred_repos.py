from requests import get, post

for page in range(1000):
    url = f"https://api.github.com/search/repositories?q=stars:>1000%20language:Python&page={page+1}"
    for index, repo in enumerate(get(url).json()["items"], start=1):
        for line in post(
            url="http://127.0.0.1:5000/process_repo",
            json={"query": repo["html_url"]},
            stream=True
        ).iter_lines():
            print(page*30+index, repo["html_url"], line)
