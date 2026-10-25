FROM python:3.12-slim
WORKDIR /app
COPY probe.py holder.py /app/
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python3", "/app/probe.py"]
