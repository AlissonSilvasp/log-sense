# syntax=docker/dockerfile:1

# Log Sense - Blue Team Log Analysis Tool
# Imagem Docker para rodar o painel de detecção de segurança

FROM python:3.11-slim

WORKDIR /app

# Copia os arquivos do projeto
COPY scripts/ scripts/
COPY dashboard.py dashboard.html collector.py convert.py ai_explain.py ./

# Cria diretórios necessários
RUN mkdir -p /app/alerts /app/reports /app/logs

# Define a porta
EXPOSE 8765

# Variáveis de ambiente
ENV PYTHONUNBUFFERED=1

# Comando padrão: iniciar o dashboard
CMD ["python", "dashboard.py"]
