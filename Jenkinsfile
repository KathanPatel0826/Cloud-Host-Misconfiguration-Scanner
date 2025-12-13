pipeline {
  agent any

  environment {
    // Where your scripts write outputs (your project currently uses "reports/")
    REPORTS_DIR   = 'reports'
    SUMMARY_IN    = 'reports/combined_summary.json'

    REPORT_HTML   = 'reports/risk_report.html'
    REPORT_PDF    = 'reports/risk_report.pdf'
    RISK_SUMMARY  = 'reports/risk_summary.json'

    // Dashboard backend (MUST be reachable from the Jenkins runtime)
    // Do NOT use 127.0.0.1 unless the Flask server is running inside the SAME Jenkins container/node.
    BACKEND_URL   = 'http://192.168.31.128:8088/ingest'
    API_TOKEN     = 'MYTOKEN'
  }

  options {
    timestamps()
    ansiColor('xterm')
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Setup Python deps') {
      steps {
        sh '''
          set -e
          python3 -m venv .venv
          . .venv/bin/activate
          pip install --upgrade pip
          pip install jinja2 weasyprint requests pyyaml
        '''
      }
    }

    stage('Run Scanner (non-fatal)') {
      steps {
        sh '''
          set +e
          . .venv/bin/activate

          echo "=== Running scanner (non-fatal) ==="
          python3 main.py
          SCAN_RC=$?

          echo "Scanner exit code: ${SCAN_RC} (continuing regardless)"
          echo "[+] reports directory:"
          ls -lah reports || true

          exit 0
        '''
      }
    }

    stage('Precheck Input') {
      steps {
        sh '''
          set -e
          if [ ! -f "${SUMMARY_IN}" ]; then
            echo "ERROR: Missing ${SUMMARY_IN}"
            echo "reports directory:"
            ls -lah reports || true
            exit 2
          fi
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          set -e
          . .venv/bin/activate

          echo "=== Generating risk report from ${SUMMARY_IN} ==="
          python3 score_and_report.py --in "${SUMMARY_IN}" --out "${REPORTS_DIR}" --pdf

          echo "[+] Generated outputs:"
          ls -lah "${REPORT_HTML}" "${REPORT_PDF}" "${RISK_SUMMARY}"
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'reports/risk_report.* , reports/risk_summary.json', fingerprint: true

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

    stage('Test Dashboard Connectivity') {
      steps {
        sh '''
          set +e
          echo "[*] Testing dashboard connectivity to: ${BACKEND_URL}"
          # Just a quick TCP/HTTP check. If it fails, we still continue (non-fatal).
          curl -sS --max-time 3 -o /dev/null -w "HTTP=%{http_code}\n" "${BACKEND_URL}" || true
          exit 0
        '''
      }
    }

    stage('Push to Dashboard') {
      when {
        expression { return fileExists("${env.RISK_SUMMARY}") }
      }
      steps {
        sh '''
          set +e
          . .venv/bin/activate

          echo "[*] Preparing payload with Jenkins metadata..."
          python3 - << 'EOF'
import json, os

inp = os.environ["RISK_SUMMARY"]
with open(inp, "r") as f:
    data = json.load(f)

data["build_id"] = os.environ.get("BUILD_NUMBER")
data["job_name"] = os.environ.get("JOB_NAME")
data["build_url"] = os.environ.get("BUILD_URL")
data["artifact_url"] = os.environ.get("BUILD_URL", "") + "artifact/reports/risk_report.html"

outp = "reports/risk_summary_with_meta.json"
with open(outp, "w") as f:
    json.dump(data, f)
print("Wrote", outp)
EOF

          echo "[+] Posting summary to dashboard: ${BACKEND_URL}"
          curl -sS -X POST "${BACKEND_URL}" \
            -H "Content-Type: application/json" \
            -H "X-API-KEY: ${API_TOKEN}" \
            --data @reports/risk_summary_with_meta.json

          RC=$?
          if [ $RC -ne 0 ]; then
            echo "Dashboard push failed (non-fatal). curl rc=$RC"
          else
            echo "Dashboard push OK."
          fi

          exit 0
        '''
      }
    }
  }

  post {
    always {
      echo 'Pipeline completed.'
      sh 'ls -lah reports || true'
    }
  }
}
