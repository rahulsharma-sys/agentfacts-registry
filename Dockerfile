# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && pip install --no-cache-dir "uvicorn[standard]"
COPY SKILL.md ./SKILL.md
ENV AGENTFACTS_DB=/app/data/agentfacts.db
ENV AGENTFACTS_SKILL_PATH=/app/SKILL.md
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["sh", "-c", "uvicorn agentfacts.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
