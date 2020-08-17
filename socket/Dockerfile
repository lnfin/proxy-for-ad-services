FROM python:3.7-alpine
ADD ./src /src
WORKDIR /src
RUN pip install -r requirements.txt
CMD ["python", "proxy_socket.py"]
