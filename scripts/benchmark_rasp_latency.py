# scripts/benchmark_rasp_latency.py — Medición de Latencia con y sin Agente RASP
# Taller WAAP: Fase 4.2 (Paso 3) y Entregable Fase 4

import os
import sys
import time
import statistics
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(BASE_DIR, "app"))

import rasp_agent

def benchmark(num_requests: int = 30):
    print("=" * 80)
    print(f"      EVALUACIÓN DE LATENCIA RASP (N={num_requests} peticiones por escenario)")
    print("=" * 80)

    # 1. Escenario SIN RASP
    rasp_agent.set_rasp_status(False)
    latencies_without = []
    for _ in range(num_requests):
        t0 = time.perf_counter()
        # Llamada a la función de construcción de consulta
        _ = rasp_agent.build_login_query("cliente_normal", "clave_segura_123")
        t1 = time.perf_counter()
        latencies_without.append((t1 - t0) * 1000) # milisegundos

    # 2. Escenario CON RASP ACTIVO
    rasp_agent.set_rasp_status(True)
    latencies_with = []
    for _ in range(num_requests):
        t0 = time.perf_counter()
        # Llamada inspeccionada en runtime por el agente RASP
        _ = rasp_agent.build_login_query("cliente_normal", "clave_segura_123")
        t1 = time.perf_counter()
        latencies_with.append((t1 - t0) * 1000) # milisegundos

    # Cálculo de métricas estadísticas
    stats_without = {
        "Media (ms)": statistics.mean(latencies_without),
        "Mediana (ms)": statistics.median(latencies_without),
        "P95 (ms)": statistics.quantiles(latencies_without, n=20)[18],
        "Mínimo (ms)": min(latencies_without),
        "Máximo (ms)": max(latencies_without)
    }

    stats_with = {
        "Media (ms)": statistics.mean(latencies_with),
        "Mediana (ms)": statistics.median(latencies_with),
        "P95 (ms)": statistics.quantiles(latencies_with, n=20)[18],
        "Mínimo (ms)": min(latencies_with),
        "Máximo (ms)": max(latencies_with)
    }

    diff_mean = stats_with["Media (ms)"] - stats_without["Media (ms)"]
    overhead_pct = (diff_mean / stats_without["Media (ms)"]) * 100 if stats_without["Media (ms)"] > 0 else 0

    results_table = [
        {"Métrica": "Media (ms)", "Sin RASP": f"{stats_without['Media (ms)']:.4f}", "Con RASP": f"{stats_with['Media (ms)']:.4f}", "Diferencia": f"+{diff_mean:.4f} ms"},
        {"Métrica": "Mediana (ms)", "Sin RASP": f"{stats_without['Mediana (ms)']:.4f}", "Con RASP": f"{stats_with['Mediana (ms)']:.4f}", "Diferencia": f"+{(stats_with['Mediana (ms)'] - stats_without['Mediana (ms)']):.4f} ms"},
        {"Métrica": "P95 (ms)", "Sin RASP": f"{stats_without['P95 (ms)']:.4f}", "Con RASP": f"{stats_with['P95 (ms)']:.4f}", "Diferencia": f"+{(stats_with['P95 (ms)'] - stats_without['P95 (ms)']):.4f} ms"},
        {"Métrica": "Mínimo (ms)", "Sin RASP": f"{stats_without['Mínimo (ms)']:.4f}", "Con RASP": f"{stats_with['Mínimo (ms)']:.4f}", "Diferencia": f"+{(stats_with['Mínimo (ms)'] - stats_without['Mínimo (ms)']):.4f} ms"},
        {"Métrica": "Máximo (ms)", "Sin RASP": f"{stats_without['Máximo (ms)']:.4f}", "Con RASP": f"{stats_with['Máximo (ms)']:.4f}", "Diferencia": f"+{(stats_with['Máximo (ms)'] - stats_without['Máximo (ms)']):.4f} ms"},
    ]

    header = "| Métrica | Sin RASP | Con RASP | Impacto / Overhead |"
    divider = "| :--- | :---: | :---: | :---: |"
    lines = [header, divider]
    for r in results_table:
        lines.append(f"| {r['Métrica']:<15} | {r['Sin RASP']:<12} | {r['Con RASP']:<12} | {r['Diferencia']:<18} |")
    
    table_str = "\n".join(lines)
    print(table_str)
    print("-" * 80)
    print(f"Overhead estimado de instrumentación RASP: {overhead_pct:.2f}% (aprox. {diff_mean*1000:.1f} microsegundos por invocación)")
    print("=" * 80)

    # Guardar reporte
    out_file = os.path.join(BASE_DIR, "logs", "latencia_rasp_benchmark.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("# Comparativa de Latencia con y sin Agente RASP (Fase 4)\n\n" + table_str + "\n\n" + f"**Overhead medio:** {diff_mean:.4f} ms por operación ({overhead_pct:.2f}%).\n")
    print(f"[+] Reporte guardado en: {out_file}")

if __name__ == '__main__':
    benchmark(num_requests=30)

