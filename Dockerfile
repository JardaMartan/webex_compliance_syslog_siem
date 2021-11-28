FROM python:latest

LABEL maintainer="@jardamartan"

WORKDIR /code

# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip install -r requirements.txt

COPY .env_docker .env

# copy the content of the local src directory to the working directory
COPY src/ .

# command to run on container start
# CMD [ "dotenv", "-f", ".env_docker", "run", "python", "wxt_compliance.py", "-vv", "-cm" ]
CMD [ "wxt_compliance.py", "-vv", "-cm" ]
