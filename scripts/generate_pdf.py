#!/usr/bin/env python3
"""Gera um PDF com o log de analise para teste."""
from fpdf import FPDF

class LogPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(0, 51, 102)
        self.cell(0, 10, 'log-sense - Log de Analise para Blue Team', align='C')
        self.ln(5)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 7, 'Laboratorio interno - Simulacao de ataques (Red Team -> Blue Team)', align='C')
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Pagina {self.page_no()}/{{nb}} - log-sense', align='C')

    def section(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(0, 51, 102)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, f'  {title}', fill=True, ln=True)
        self.set_text_color(0, 0, 0)

# Ler o log
with open('samples/attack_analysis.txt', 'r', encoding='utf-8') as f:
    log_content = f.read()

lines = log_content.split('\n')

# Gerar PDF
pdf = LogPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# Titulo
pdf.set_font('Helvetica', 'B', 18)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 12, 'log-sense - Log de Analise para Blue Team', align='C')
pdf.ln(10)

# Metadados
pdf.set_font('Helvetica', 'B', 9)
pdf.set_text_color(80, 80, 80)
pdf.cell(0, 7, 'Data: 2026-11-11 08:00:00 | Ambiente: laboratorio | Total de linhas: 120', align='C')
pdf.ln(9)

# Resumo dos alerts
pdf.set_font('Helvetica', 'B', 13)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, 'Resumo dos Alertas Detectados', align='C')
pdf.ln(14)

pdf.set_font('Helvetica', '', 9)
pdf.set_text_color(0, 0, 0)

alerts_summary = [
    ('HIGH', 'brute_force', '30 tentativas de login falhas (SSH brute force)'),
    ('HIGH', 'brute_force', '7 tentativas de login falhas (user enumeration)'),
    ('HIGH', 'sensitive_file_access', '/etc/shadow acessado'),
    ('HIGH', 'sensitive_file_access', '/etc/passwd acessado'),
    ('HIGH', 'sensitive_file_access', '/etc/sudoers acessado'),
    ('HIGH', 'sensitive_file_access', '/root/.ssh/authorized_keys acessado'),
    ('HIGH', 'sqli_query', 'Injecao SQL detectada (UNION SELECT, DROP TABLE)'),
    ('HIGH', 'unauthorized_access', 'Acesso nao autorizado a /admin (15x)'),
    ('MEDIUM', 'xss_reflected', 'Possivel XSS reflectida (script, javascript, onerror)'),
    ('MEDIUM', 'user_enumeration', '7 usuarios diferentes tentaram login falho'),
]

pdf.set_font('Helvetica', 'B', 10)
pdf.set_fill_color(0, 51, 102)
pdf.set_text_color(255, 255, 255)
pdf.cell(0, 8, '  RESUMO GERAL', fill=True, ln=True)
pdf.ln(5)

for severity, rule, desc in alerts_summary:
    if severity == 'HIGH':
        pdf.set_fill_color(180, 40, 40)
        pdf.set_text_color(255, 255, 255)
    else:
        pdf.set_fill_color(180, 140, 0)
        pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, f'  [{severity}] {rule}: {desc}', fill=True, ln=True)

pdf.ln(8)
pdf.set_draw_color(0, 51, 102)
pdf.set_line_width(0.5)
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(8)

# Log completo
pdf.set_font('Helvetica', 'B', 12)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, 'Log Completo - Attack Analysis', align='C')
pdf.ln(12)

pdf.set_font('Helvetica', '', 8)
pdf.set_text_color(60, 60, 60)

for line in lines:
    line = line.strip()
    if not line:
        continue
    if line.startswith('# ---') or line.startswith('# ==='):
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(180, 180, 180)
        pdf.cell(0, 7, line, ln=True)
    elif 'result=' in line:
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(0, 6, line, ln=True)
    else:
        pdf.set_font('Helvetica', 'I', 7)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 6, line, ln=True)

pdf.output('log-analysis.pdf')
print('PDF gerado: log-analysis.pdf')
print(f'Tamanho: {pdf.get_string_width("T")}')
