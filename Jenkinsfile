pipeline {
  agent any

  environment {
    // Gate policy
    MAX_TOTAL_SCORE = '1000'
    MIN_PASS_GRADE  = 'F'
    ENFORCE_GATE    = 'true'   // set to 'false' to bypass the gate

    // Repo paths (YOUR PROJECT USES reports/)
    REPORTS_DIR     = 'reports'
    AWS_SCAN_JSON   = 'reports/aws_scan.json'
    COMBINED_JSON   = 'reports/combined_findings.json'
    REPORT_HTML     = 'reports/risk_report.html'
    REPORT_PDF      = 'reports/risk_report.pdf'
    SUMMARY_JSON    = 'reports/risk_summary.json'

    // Dashboard backend (set to host IP if Jenkins is in Docker)
    DASHBOARD_URL   = 'http://127.0.0.1:8088/ingest'
    API_TOKEN       = 'MYTOKEN'
  }

  stages {

    stage('Init (clear old params)') {
      steps {
        script {
          properties([])
          echo 'Cleared leftover job parameters.'
        }
      }
    }

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Setup Python deps') {
      steps {
        sh '''
          python3 -m venv .venv || true
          . .venv/bin/activate
          pip install --upgrade pip
          pip install jinja2 weasyprint requests || true
        '''
      }
    }

    stage('Security Scan + Normalize') {
      steps {
        sh '''
          . .venv/bin/activate

          # 1) Run scanners (AWS via Prowler + Linux via Lynis if applicable)
          python3 main.py

          # 2) Normalize Prowler output into reports/aws_scan.json
          #    (your convert_prowler_output.py writes to reports/aws_scan.json)
          python3 convert_prowler_output.py

          # 3) Build combined findings list into reports/combined_findings.json
          python3 -m utils.build_findings

          echo "[+] Listing reports directory"
          ls -lah reports || true
        '''
      }
    }

    stage('Precheck Inputs') {
      steps {
        sh '''
          if [ ! -f "${COMBINED_JSON}" ]; then
            echo "ERROR: Missing ${COMBINED_JSON}"
            echo "reports/ directory:"
            ls -lah reports || true
            exit 2
          fi
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          . .venv/bin/activate
          python3 score_and_report.py --in "${COMBINED_JSON}" --out "${REPORTS_DIR}" --pdf || \
          python3 score_and_report.py --in "${COMBINED_JSON}" --out "${REPORTS_DIR}"
          echo "[+] Generated:"
          ls -lah reports/risk_report.* reports/risk_summary.json || true
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'reports/risk_report.*', fingerprint: true
        publishHTML(target: [
          reportDir: 'reports',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report',
          keepAll: true,
          alwaysLinkToLastBuild: true,
          allowMissing: false
        ])
      }
    }

    stage('Push to Dashboard') {
      when {
        expression { return fileExists(env.SUMMARY_JSON) }
      }
      steps {
        sh '''
          . .venv/bin/activate

          python3 - << 'EOF'
import json, os

summary_path = "reports/risk_summary.json"
with open(summary_path) as f:
    data = json.load(f)

data["build_id"] = os.environ.get("BUILD_NUMBER")
data["job_name"] = os.environ.get("JOB_NAME")
data["build_url"] = os.environ.get("BUILD_URL")
data["artifact_url"] = (os.environ.get("BUILD_URL") or "") + "artifact/reports/risk_report.html"

out_path = "reports/risk_summary_with_meta.json"
with open(out_path, "w") as f:
    json.dump(data, f, indent=2)
print("Wrote", out_path)
EOF

          echo "[+] Posting to dashboard: ${DASHBOARD_URL}"
          curl -sS -X POST "${DASHBOARD_URL}" \
            -H "Content-Type: application/json" \
            -H "X-API-KEY: ${API_TOKEN}" \
            --data @reports/risk_summary_with_meta.json \
            || echo "Dashboard push failed (non-fatal)"
        '''
      }
    }

    stage('Quality Gate') {
      when { expression { return env.ENFORCE_GATE == 'true' } }
      steps {
        script {
          // Read from risk_summary.json (more reliable than grepping HTML)
          def totalScore = sh(
            script: "python3 -c \"import json; print(json.load(open('reports/risk_summary.json'))['score'])\"",
            returnStdout: true
