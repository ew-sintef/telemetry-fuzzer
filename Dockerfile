FROM python:3.9

RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

WORKDIR /fuzzenv

COPY requirements.txt /fuzzenv/requirements.txt
RUN pip install --no-cache-dir -r /fuzzenv/requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

