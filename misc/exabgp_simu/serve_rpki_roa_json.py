#!/usr/bin/env python3

import io
import os
import pathlib

from flask import Flask, send_file

app = Flask(__name__)

this_file_dir = pathlib.Path(__file__).parent.absolute()
validated_roas = os.path.join(this_file_dir, "my_validated_roas.json")


@app.route('/rpki.json')
def send_json():
    with open(validated_roas, 'rb') as f:
        my_stream = io.BytesIO(f.read())

        return send_file(
            my_stream,
            attachment_filename='rpki.json',
            mimetype="binary/octet-stream"
        )


if __name__ == '__main__':
    app.run(port=8081)
