import click
import pandas as pd
import json
from detector import analyze_url
from siem_alerter import send_cef_alert

# --- [NEW] Helper function for a beautiful single result display ---
def display_single_result(results):
    """Formats and prints a single, detailed analysis report."""
    
    # Header
    click.echo(click.style("\n M L  A N A L Y S I S", bold=True, fg='cyan'))
    click.echo("---------------------------------")
    
    # ML Verdict
    verdict_color = 'red' if results['ml_verdict'] == "Phishing" else 'green'
    click.echo(f"  🔬 Verdict:    {click.style(results['ml_verdict'], fg=verdict_color)}")
    click.echo(f"  📈 Confidence: {results['confidence']:.2f}%")

    # API Intelligence
    click.echo(click.style("\n A P I  I N T E L L I G E N C E", bold=True, fg='cyan'))
    click.echo("---------------------------------")
    
    # VirusTotal
    vt_status = results['virustotal_status']
    vt_color = 'red' if vt_status == "MALICIOUS" else ('yellow' if vt_status == "NOT_FOUND" else 'green')
    click.echo(f"  📡 VirusTotal: {click.style(results['virustotal_reason'], fg=vt_color)}")
    
    # Google Safe Browsing
    gsb_status = results['google_safe_browsing_status']
    gsb_color = 'red' if gsb_status == "MALICIOUS" else ('magenta' if gsb_status == "API_ERROR" else 'green')
    click.echo(f"  🌐 Google Safe Browsing: {click.style(results['google_safe_browsing_reason'], fg=gsb_color)}")

    # Final Verdict
    click.echo(click.style("\n F I N A L  V E R D I C T", bold=True, fg='cyan'))
    click.echo("---------------------------------")
    if results['final_verdict'] == "PHISHING DETECTED":
        click.echo(click.style("  🚨 PHISHING DETECTED", fg='red', bold=True, blink=True))
    else:
        click.echo(click.style("  ✅ LEGITIMATE", fg='green', bold=True))
    click.echo()


@click.command()
@click.option('--url', type=str, help="A single URL to analyze.")
@click.option('--input-file', type=click.Path(exists=True), help="Path to a text file with one URL per line.")
@click.option('--output-file', type=click.Path(), help="Path to save the results as a CSV file.")
@click.option('--siem', is_flag=True, help="Send a CEF alert to the SIEM if phishing is detected.")
@click.option('--json-output', is_flag=True, help="Output the results in JSON format.")
def detect_phishing(url, input_file, output_file, siem, json_output):
    """
    A powerful phishing detection tool created by rizz.
    Supports single URLs, batch processing, and multiple output formats.
    """
    click.echo(click.style("\n🎣 Phishing Detector ML Tool | Created by farixzz\n", bold=True, fg='bright_blue'))

    urls_to_process = []
    if url:
        urls_to_process.append(url)
    elif input_file:
        with open(input_file, 'r') as f:
            urls_to_process = [line.strip() for line in f if line.strip()]
        click.echo(f"Loaded {len(urls_to_process)} URLs from {input_file}")
    else:
        click.echo("Error: Please provide a URL with --url or a file with --input-file.", err=True)
        return

    all_results = []
    
    if len(urls_to_process) == 1:
        # --- Clean single URL analysis ---
        current_url = urls_to_process[0]
        with click.progressbar(length=1, label=f'Analyzing {current_url[:50]}...') as bar:
            results = analyze_url(current_url)
            bar.update(1)
        
        all_results.append(results)
        
        if not json_output:
            display_single_result(results)
        
        if results['final_verdict'] == "PHISHING DETECTED" and siem:
            send_cef_alert(current_url, results['confidence'], results['ml_verdict'])
    else:
        # --- Clean batch analysis with progress bar ---
        with click.progressbar(urls_to_process, label='Analyzing URLs...', item_show_func=lambda item: f"Processing {item[:40]}..." if item else "") as bar:
            for current_url in bar:
                results = analyze_url(current_url)
                all_results.append(results)
                if results['final_verdict'] == "PHISHING DETECTED" and siem:
                    send_cef_alert(current_url, results['confidence'], results['ml_verdict'])
        
        if not json_output:
            click.echo(click.style("\n---[ Batch Analysis Summary ]---", bold=True))
            df = pd.DataFrame(all_results)
            # Add a verdict icon for quick scanning
            df['Verdict'] = df['final_verdict'].apply(lambda v: '🚨' if v == 'PHISHING DETECTED' else '✅')
            # Display a clean, focused table
            click.echo(df[['Verdict', 'url', 'ml_verdict', 'confidence']].to_string(index=False))
            click.echo()

    # --- Output Handling ---
    if json_output:
        output = all_results[0] if len(all_results) == 1 else all_results
        click.echo(json.dumps(output, indent=2))

    if output_file:
        df = pd.DataFrame(all_results)
        df.to_csv(output_file, index=False)
        click.echo(f"\n✅ Results saved to {output_file}\n")

if __name__ == '__main__':
    detect_phishing()
