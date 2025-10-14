#!/usr/bin/env python3
"""
Enhanced Browser Forensics Report Generator with Visualizations

This script generates professional forensic reports with:
- Interactive charts and graphs
- Multiple output formats (Markdown, PDF, HTML)
- Visual timeline analysis
- Risk assessment visualizations

Author: Browser Forensics Project
Date: October 2025
"""

import os
import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.offline as pyo
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import markdown

class EnhancedForensicReportGenerator:
    """Enhanced class for generating forensic reports with visualizations."""

    def __init__(self, analysis_dir="../data/processed", output_dir="../reports"):
        self.analysis_dir = Path(analysis_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.charts_dir = self.output_dir / "charts"
        self.charts_dir.mkdir(exist_ok=True)

        # Set up plotting style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")

        # Load analysis data
        self.load_analysis_data()

    def load_analysis_data(self):
        """Load processed analysis data."""
        try:
            with open(self.analysis_dir / 'forensic_analysis_report.json', 'r', encoding='utf-8') as f:
                self.report_data = json.load(f)
        except FileNotFoundError:
            print("Error: Analysis report not found. Run analyze_artifacts.py first.")
            self.report_data = None

        try:
            with open(self.analysis_dir / 'user_sessions.json', 'r', encoding='utf-8') as f:
                self.session_data = json.load(f)
        except FileNotFoundError:
            self.session_data = None

        # Load timeline data
        self.timeline_data = []
        timeline_file = self.analysis_dir / 'timeline_events.csv'
        if timeline_file.exists():
            with open(timeline_file, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row.get('timestamp'):
                        try:
                            row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                        except ValueError:
                            pass
                    self.timeline_data.append(row)

    def create_timeline_chart(self):
        """Create interactive timeline visualization."""
        if not self.timeline_data:
            return None

        # Prepare data for timeline
        timeline_df = pd.DataFrame(self.timeline_data)
        timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')
        timeline_df = timeline_df.dropna(subset=['timestamp'])

        # Group by hour for activity heatmap
        timeline_df['hour'] = timeline_df['timestamp'].dt.hour
        timeline_df['date'] = timeline_df['timestamp'].dt.date

        # Create activity heatmap
        activity_pivot = timeline_df.groupby(['date', 'hour']).size().unstack(fill_value=0)
        
        fig = px.imshow(
            activity_pivot.T,
            labels=dict(x="Date", y="Hour", color="Activity Count"),
            title="Browser Activity Heatmap by Date and Hour",
            color_continuous_scale="Reds"
        )
        
        fig.update_layout(
            height=600,
            xaxis_title="Date",
            yaxis_title="Hour of Day",
            title_x=0.5
        )

        chart_path = self.charts_dir / "timeline_heatmap.html"
        fig.write_html(str(chart_path))
        
        # Also create a static version
        plt.figure(figsize=(12, 8))
        sns.heatmap(activity_pivot.T, cmap='Reds', cbar_kws={'label': 'Activity Count'})
        plt.title('Browser Activity Heatmap by Date and Hour')
        plt.xlabel('Date')
        plt.ylabel('Hour of Day')
        plt.tight_layout()
        plt.savefig(self.charts_dir / "timeline_heatmap.png", dpi=300, bbox_inches='tight')
        plt.close()

        return "timeline_heatmap.html"

    def create_domain_analysis_charts(self):
        """Create domain analysis visualizations."""
        if not self.report_data:
            return []

        domain_analysis = self.report_data.get('domain_analysis', {})
        top_domains = domain_analysis.get('top_domains', [])[:15]
        suspicious_domains = domain_analysis.get('suspicious_domains', {})

        charts = []

        # Top domains bar chart
        if top_domains:
            domains, visits = zip(*top_domains)
            
            fig = px.bar(
                x=visits, y=domains,
                orientation='h',
                title="Top 15 Most Visited Domains",
                labels={'x': 'Number of Visits', 'y': 'Domain'}
            )
            fig.update_layout(height=600, title_x=0.5)
            
            chart_path = self.charts_dir / "top_domains.html"
            fig.write_html(str(chart_path))
            charts.append("top_domains.html")

            # Static version
            plt.figure(figsize=(10, 8))
            plt.barh(range(len(domains)), visits)
            plt.yticks(range(len(domains)), domains)
            plt.xlabel('Number of Visits')
            plt.title('Top 15 Most Visited Domains')
            plt.tight_layout()
            plt.savefig(self.charts_dir / "top_domains.png", dpi=300, bbox_inches='tight')
            plt.close()

        # Suspicious domains risk analysis
        if suspicious_domains:
            risk_data = []
            for domain, data in suspicious_domains.items():
                risk_data.append({
                    'domain': domain,
                    'risk_level': data.get('risk_level', 0),
                    'visits': data.get('stats', {}).get('visits', 0),
                    'risk_factors': len(data.get('risk_factors', []))
                })

            risk_df = pd.DataFrame(risk_data)
            
            fig = px.scatter(
                risk_df, x='visits', y='risk_level',
                size='risk_factors', hover_data=['domain'],
                title="Suspicious Domains Risk Analysis",
                labels={'visits': 'Number of Visits', 'risk_level': 'Risk Level'}
            )
            fig.update_layout(height=500, title_x=0.5)
            
            chart_path = self.charts_dir / "risk_analysis.html"
            fig.write_html(str(chart_path))
            charts.append("risk_analysis.html")

        return charts

    def create_session_analysis_charts(self):
        """Create session analysis visualizations."""
        if not self.session_data:
            return []

        sessions = self.session_data.get('sessions', [])
        if not sessions:
            return []

        charts = []

        # Session duration analysis
        session_durations = []
        for session in sessions:
            if session.get('duration'):
                try:
                    # Parse duration string (e.g., "1:23:45")
                    duration_parts = session['duration'].split(':')
                    if len(duration_parts) == 3:
                        hours, minutes, seconds = map(int, duration_parts)
                        total_minutes = hours * 60 + minutes + seconds / 60
                        session_durations.append(total_minutes)
                except:
                    continue

        if session_durations:
            plt.figure(figsize=(10, 6))
            plt.hist(session_durations, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            plt.xlabel('Session Duration (minutes)')
            plt.ylabel('Number of Sessions')
            plt.title('Distribution of Session Durations')
            plt.tight_layout()
            plt.savefig(self.charts_dir / "session_durations.png", dpi=300, bbox_inches='tight')
            plt.close()

            # Interactive version
            fig = px.histogram(
                x=session_durations,
                nbins=20,
                title="Distribution of Session Durations",
                labels={'x': 'Session Duration (minutes)', 'y': 'Number of Sessions'}
            )
            fig.update_layout(height=500, title_x=0.5)
            
            chart_path = self.charts_dir / "session_durations.html"
            fig.write_html(str(chart_path))
            charts.append("session_durations.html")

        # Peak activity hours
        peak_hours = self.session_data.get('session_stats', {}).get('peak_activity_hours', {})
        if peak_hours:
            hours = list(range(24))
            counts = [peak_hours.get(str(h), 0) for h in hours]
            
            fig = px.bar(
                x=hours, y=counts,
                title="Peak Activity Hours",
                labels={'x': 'Hour of Day', 'y': 'Number of Sessions'}
            )
            fig.update_layout(height=500, title_x=0.5)
            
            chart_path = self.charts_dir / "peak_hours.html"
            fig.write_html(str(chart_path))
            charts.append("peak_hours.html")

        return charts

    def create_download_analysis_charts(self):
        """Create download analysis visualizations."""
        if not self.report_data:
            return []

        download_analysis = self.report_data.get('download_analysis', {})
        file_breakdown = download_analysis.get('file_type_breakdown', {})
        suspicious_downloads = download_analysis.get('suspicious_downloads', [])

        charts = []

        # File type breakdown pie chart
        if file_breakdown:
            fig = px.pie(
                values=list(file_breakdown.values()),
                names=list(file_breakdown.keys()),
                title="Download File Type Breakdown"
            )
            fig.update_layout(height=500, title_x=0.5)
            
            chart_path = self.charts_dir / "file_types.html"
            fig.write_html(str(chart_path))
            charts.append("file_types.html")

        # Suspicious downloads timeline
        if suspicious_downloads:
            download_times = []
            for download in suspicious_downloads:
                if download.get('start_time'):
                    try:
                        download_times.append(datetime.fromisoformat(download['start_time']))
                    except:
                        continue

            if download_times:
                plt.figure(figsize=(12, 6))
                plt.hist(download_times, bins=20, alpha=0.7, color='red', edgecolor='black')
                plt.xlabel('Date')
                plt.ylabel('Number of Suspicious Downloads')
                plt.title('Timeline of Suspicious Downloads')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(self.charts_dir / "suspicious_downloads.png", dpi=300, bbox_inches='tight')
                plt.close()

        return charts

    def generate_markdown_report(self, case_number="BF-2025-001", investigator="Browser Forensics Team"):
        """Generate Markdown format report."""
        if not self.report_data:
            return None

        # Create all charts first
        timeline_chart = self.create_timeline_chart()
        domain_charts = self.create_domain_analysis_charts()
        session_charts = self.create_session_analysis_charts()
        download_charts = self.create_download_analysis_charts()

        report_content = []

        # Header
        report_content.append(f"# Browser Forensics Incident Report")
        report_content.append(f"**Case Number:** {case_number}  ")
        report_content.append(f"**Report Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        report_content.append(f"**Investigator:** {investigator}  ")
        report_content.append(f"**Analysis Tool:** Browser Forensics Analysis Suite v2.0  ")
        report_content.append("")
        report_content.append("---")
        report_content.append("")

        # Executive Summary
        summary = self.report_data.get('summary', {})
        report_content.append("## Executive Summary")
        report_content.append("")
        report_content.append("This report presents the findings of a digital forensic analysis of browser artifacts")
        report_content.append("extracted from a test machine. The analysis focused on reconstructing user activity")
        report_content.append("patterns, identifying suspicious behaviors, and demonstrating the persistence of")
        report_content.append("browser data despite deletion attempts.")
        report_content.append("")
        report_content.append("### Key Metrics")
        report_content.append(f"- **Total browsing history records analyzed:** {summary.get('total_history_records', 0):,}")
        report_content.append(f"- **Total download records examined:** {summary.get('total_download_records', 0):,}")
        report_content.append(f"- **Total cookie records reviewed:** {summary.get('total_cookie_records', 0):,}")
        report_content.append(f"- **Unique domains accessed:** {summary.get('unique_domains', 0):,}")
        report_content.append(f"- **User sessions identified:** {summary.get('user_sessions', 0):,}")
        report_content.append(f"- **Suspicious domains detected:** {summary.get('suspicious_domains', 0)}")
        report_content.append(f"- **Suspicious downloads identified:** {summary.get('suspicious_downloads', 0)}")
        report_content.append("")

        # Visualizations
        report_content.append("## Visual Analysis")
        report_content.append("")

        if timeline_chart:
            report_content.append("### Timeline Analysis")
            report_content.append(f"![Timeline Heatmap](charts/timeline_heatmap.png)")
            report_content.append("")
            report_content.append(f"[Interactive Timeline Chart](charts/{timeline_chart})")
            report_content.append("")

        if domain_charts:
            report_content.append("### Domain Analysis")
            for chart in domain_charts:
                if "top_domains" in chart:
                    report_content.append(f"![Top Domains](charts/top_domains.png)")
                    report_content.append(f"[Interactive Chart](charts/{chart})")
                elif "risk_analysis" in chart:
                    report_content.append(f"[Risk Analysis Chart](charts/{chart})")
            report_content.append("")

        if session_charts:
            report_content.append("### Session Analysis")
            for chart in session_charts:
                if "session_durations" in chart:
                    report_content.append(f"![Session Durations](charts/session_durations.png)")
                    report_content.append(f"[Interactive Chart](charts/{chart})")
                elif "peak_hours" in chart:
                    report_content.append(f"[Peak Activity Hours](charts/{chart})")
            report_content.append("")

        if download_charts:
            report_content.append("### Download Analysis")
            for chart in download_charts:
                if "file_types" in chart:
                    report_content.append(f"[File Type Breakdown](charts/{chart})")
                elif "suspicious_downloads" in chart:
                    report_content.append(f"![Suspicious Downloads Timeline](charts/suspicious_downloads.png)")
            report_content.append("")

        # Findings
        report_content.append("## Key Findings")
        report_content.append("")

        key_findings = self.report_data.get('key_findings', [])
        if key_findings:
            for i, finding in enumerate(key_findings, 1):
                severity = finding.get('severity', 'UNKNOWN')
                category = finding.get('category', 'Unknown')
                description = finding.get('description', '')
                
                report_content.append(f"### {i}. {severity} SEVERITY: {category}")
                report_content.append(f"{description}")
                if finding.get('details'):
                    report_content.append(f"**Details:** {finding.get('details')}")
                report_content.append("")

        # Methodology
        report_content.append("## Methodology")
        report_content.append("")
        report_content.append("### Data Acquisition")
        report_content.append("Browser artifacts were extracted using custom Python scripts designed to")
        report_content.append("access browser databases safely without modifying original files.")
        report_content.append("")
        report_content.append("### Analysis Techniques")
        report_content.append("- Chronological timeline construction from multiple data sources")
        report_content.append("- Domain pattern analysis for suspicious activity detection")
        report_content.append("- Download pattern analysis for malware indicators")
        report_content.append("- Session analysis for user behavior patterns")
        report_content.append("- Risk assessment using predefined suspicious indicators")
        report_content.append("")

        # Conclusions
        report_content.append("## Conclusions")
        report_content.append("")
        report_content.append("This analysis demonstrates that browser artifacts provide significant forensic value")
        report_content.append("in reconstructing user activity, even when users attempt to delete their browsing data.")
        report_content.append("")
        report_content.append("Key conclusions include:")
        report_content.append("1. **Persistence of Data:** Browser artifacts remain accessible through multiple storage mechanisms")
        report_content.append("2. **Timeline Reconstruction:** Detailed timelines can be reconstructed from correlated timestamps")
        report_content.append("3. **Suspicious Activity Detection:** Pattern analysis can identify potentially malicious behavior")
        report_content.append("4. **Privacy Implications:** Extensive tracking data reveals surveillance levels")
        report_content.append("5. **Investigative Techniques:** Automated tools provide comprehensive examination capabilities")
        report_content.append("")

        return "\n".join(report_content)

    def generate_pdf_report(self, case_number="BF-2025-001", investigator="Browser Forensics Team"):
        """Generate PDF format report."""
        if not self.report_data:
            return None

        # Create charts first
        self.create_timeline_chart()
        self.create_domain_analysis_charts()
        self.create_session_analysis_charts()
        self.create_download_analysis_charts()

        # Create PDF
        pdf_path = self.output_dir / f"browser_forensics_report_{case_number}.pdf"
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("Browser Forensics Incident Report", title_style))
        story.append(Spacer(1, 12))

        # Case info
        case_info = f"""
        <b>Case Number:</b> {case_number}<br/>
        <b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Investigator:</b> {investigator}<br/>
        <b>Analysis Tool:</b> Browser Forensics Analysis Suite v2.0
        """
        story.append(Paragraph(case_info, styles['Normal']))
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary = self.report_data.get('summary', {})
        summary_text = f"""
        This report presents the findings of a digital forensic analysis of browser artifacts
        extracted from a test machine. The analysis focused on reconstructing user activity
        patterns, identifying suspicious behaviors, and demonstrating the persistence of
        browser data despite deletion attempts.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 12))

        # Key metrics table
        metrics_data = [
            ['Metric', 'Value'],
            ['Total history records', f"{summary.get('total_history_records', 0):,}"],
            ['Total download records', f"{summary.get('total_download_records', 0):,}"],
            ['Total cookie records', f"{summary.get('total_cookie_records', 0):,}"],
            ['Unique domains accessed', f"{summary.get('unique_domains', 0):,}"],
            ['User sessions identified', f"{summary.get('user_sessions', 0):,}"],
            ['Suspicious domains detected', f"{summary.get('suspicious_domains', 0)}"],
            ['Suspicious downloads identified', f"{summary.get('suspicious_downloads', 0)}"]
        ]

        metrics_table = Table(metrics_data)
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 20))

        # Add charts if they exist
        chart_files = [
            ("timeline_heatmap.png", "Timeline Analysis"),
            ("top_domains.png", "Top Visited Domains"),
            ("session_durations.png", "Session Duration Distribution"),
            ("suspicious_downloads.png", "Suspicious Downloads Timeline")
        ]

        for chart_file, title in chart_files:
            chart_path = self.charts_dir / chart_file
            if chart_path.exists():
                story.append(Paragraph(title, styles['Heading3']))
                img = Image(str(chart_path), width=6*inch, height=4*inch)
                story.append(img)
                story.append(Spacer(1, 12))

        # Key findings
        story.append(Paragraph("Key Findings", styles['Heading2']))
        key_findings = self.report_data.get('key_findings', [])
        if key_findings:
            for i, finding in enumerate(key_findings, 1):
                severity = finding.get('severity', 'UNKNOWN')
                category = finding.get('category', 'Unknown')
                description = finding.get('description', '')
                
                finding_text = f"""
                <b>{i}. {severity} SEVERITY: {category}</b><br/>
                {description}
                """
                story.append(Paragraph(finding_text, styles['Normal']))
                story.append(Spacer(1, 6))

        # Build PDF
        doc.build(story)
        return pdf_path

    def generate_html_report(self, case_number="BF-2025-001", investigator="Browser Forensics Team"):
        """Generate HTML format report."""
        markdown_content = self.generate_markdown_report(case_number, investigator)
        if not markdown_content:
            return None

        # Convert markdown to HTML
        html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])

        # Add CSS styling
        styled_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Browser Forensics Report - {case_number}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    line-height: 1.6;
                }}
                h1 {{
                    color: #2c3e50;
                    border-bottom: 3px solid #3498db;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #34495e;
                    border-bottom: 2px solid #ecf0f1;
                    padding-bottom: 5px;
                }}
                h3 {{
                    color: #7f8c8d;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }}
                th {{
                    background-color: #3498db;
                    color: white;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .chart-container {{
                    text-align: center;
                    margin: 20px 0;
                }}
                img {{
                    max-width: 100%;
                    height: auto;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                .footer {{
                    margin-top: 50px;
                    padding-top: 20px;
                    border-top: 1px solid #ecf0f1;
                    color: #7f8c8d;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            {html_content}
            <div class="footer">
                <p>Generated by Browser Forensics Analysis Suite v2.0</p>
                <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </body>
        </html>
        """

        html_path = self.output_dir / f"browser_forensics_report_{case_number}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(styled_html)

        return html_path

    def generate_all_formats(self, case_number="BF-2025-001", investigator="Browser Forensics Team"):
        """Generate all report formats."""
        if not self.report_data:
            print("Error: No analysis data found. Please run analysis first.")
            return

        print("Generating enhanced forensic reports...")
        print("Creating visualizations...")

        # Generate all formats
        markdown_path = self.output_dir / f"browser_forensics_report_{case_number}.md"
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_markdown_report(case_number, investigator))

        pdf_path = self.generate_pdf_report(case_number, investigator)
        html_path = self.generate_html_report(case_number, investigator)

        print(f"Reports generated:")
        print(f"- Markdown: {markdown_path}")
        print(f"- PDF: {pdf_path}")
        print(f"- HTML: {html_path}")
        print(f"- Charts directory: {self.charts_dir}")

        return {
            'markdown': markdown_path,
            'pdf': pdf_path,
            'html': html_path,
            'charts': self.charts_dir
        }

def main():
    parser = argparse.ArgumentParser(description='Generate enhanced forensic reports with visualizations')
    parser.add_argument('-a', '--analysis', default='../data/processed',
                       help='Analysis data directory (default: ../data/processed)')
    parser.add_argument('-o', '--output', default='../reports',
                       help='Output directory for reports (default: ../reports)')
    parser.add_argument('-c', '--case', default='BF-2025-001',
                       help='Case number for the report (default: BF-2025-001)')
    parser.add_argument('-i', '--investigator', default='Browser Forensics Team',
                       help='Investigator name (default: Browser Forensics Team)')
    parser.add_argument('-f', '--format', choices=['markdown', 'pdf', 'html', 'all'],
                       default='all', help='Output format (default: all)')

    args = parser.parse_args()

    generator = EnhancedForensicReportGenerator(args.analysis, args.output)

    if not generator.report_data:
        print("Error: No analysis data found. Please run analysis first.")
        return

    if args.format == 'all':
        generator.generate_all_formats(args.case, args.investigator)
    elif args.format == 'markdown':
        markdown_content = generator.generate_markdown_report(args.case, args.investigator)
        markdown_path = generator.output_dir / f"browser_forensics_report_{args.case}.md"
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"Markdown report saved: {markdown_path}")
    elif args.format == 'pdf':
        pdf_path = generator.generate_pdf_report(args.case, args.investigator)
        print(f"PDF report saved: {pdf_path}")
    elif args.format == 'html':
        html_path = generator.generate_html_report(args.case, args.investigator)
        print(f"HTML report saved: {html_path}")

if __name__ == "__main__":
    main()

