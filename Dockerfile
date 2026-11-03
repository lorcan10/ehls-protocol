FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY shared/ shared/
COPY gateway/ gateway/
COPY ehls/ ehls/
RUN python -m pip install --no-cache-dir '.[api]' && useradd --create-home ehls
USER ehls
EXPOSE 8765
CMD ["ehls", "serve", "--host", "0.0.0.0"]
