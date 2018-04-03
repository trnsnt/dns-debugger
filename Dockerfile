FROM python:3.6.5

EXPOSE 5000

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && apt-get -y install dialog apt-utils libssl-dev swig
RUN apt-get -y upgrade

RUN pip install --upgrade pip
RUN pip install pipenv
COPY . /app
WORKDIR /app
RUN pipenv install --system
ENTRYPOINT ["python"]
CMD ["-m", "dns_debugger", "-x", "server"]
