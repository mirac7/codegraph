#!/usr/bin/env python3
# coding=utf-8

from json import dumps, loads, JSONDecodeError
from threading import Thread
from flask import Flask, Response, render_template, request
from core.interface import GraphBuilder
from core.nvd import run_sync_forever
from backend.util import validate_repo_query, json_stream_wrapper

Thread(target=run_sync_forever, kwargs={"load_history": False}).start()
app = Flask(__name__)


@app.route("/get_repo_insights")
def get_repo_insights():
    query = request.args.get("query", "")
    if report := GraphBuilder(query).get_cached_report():
        return dumps({"found": True, "report": report})
    return dumps({"found": False})


@app.route("/process_repo", methods=["POST"])
def process_repo():
    try:
        query = loads(request.data)["query"]
    except (JSONDecodeError, KeyError):
        return dumps({"status": "rejected"})

    if not validate_repo_query(query):
        return dumps({"status": "rejected"})

    interface = GraphBuilder(query)
    if interface.get_cached_report():
        return dumps({"status": "cached"})

    return Response(json_stream_wrapper(interface.stream_process_repository()))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/graph")
def graph():
    return render_template("graph.html")


if __name__ == '__main__':
    app.run()
