pipeline {
  agent any

  environment {
    // Gate policy
    MAX_TOTAL_SCORE = '1000'
    MIN_PASS_GRADE  = 'F'
    ENFORCE_GATE    = 'true'   // set to 'false' to bypass the gate

    // Repo paths
    REPORTS_DIR     = 'reports'
    COMBINED_JSON   = 'reports/combined_findings.json'
    SUMMARY_JSON    = 'reports/risk_summary.json'

    // Dashboard backend (if Jenkins is in Docker, use host IP instead of 127.0.0.1)
    DASHBOARD_URL   = 'http://127.0.0.1:8088/ingest'
    API_TOKEN       = 'MYTOKEN'
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
          python3 -m venv .venv || true
          . .venv/bin/activate
          pip install --upgrade pip
          pip install jinja2 weasyprint requests pyyaml || true
        '''
      }
    }

    stage('Security Scan + Normalize') {
      steps {
        sh '''
          . .venv/bin/activate

          # Run scanners (AWS + Linux)
          python3 main.py

          # Normalize prowler output if you use it
          if [ -f convert_prowler_output.py ]; then
            python3 convert_prowler_output.py || true
          fi

          # Build combined findings if the module exists
          if [ -f utils/build_findings.py ]; then
            python3 -m utils.build_findings
          fi

          echo "[+] reports directory:"
          ls -lah reports || true
        '''
      }
    }

    stage('Precheck Inputs') {
      steps {
        sh '''
          if [ ! -f "${COMBINED_JSON}" ]; then
            echo "ERROR: Missing ${COMBINED_JSON}"
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
          . .venv/bin/activate
          python3 score_and_report.py --in "${COMBINED_JSON}" --out "${REPORTS_DIR}" --pdf || \
          python3 score_and_report.py --in "${COMBINED_JSON}" --out "${REPORTS_DIR}"

          echo "[+] Generated outputs:"
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
          allowMissing: true
        ])
      }
    }

    stage('Push to Dashboard') {
      when {
        expression { return fileExists(env.SUMMARY_JSON) }
      }
      steps {
        sh '''
          echo "[+] Posting summary to dashboard: ${DASHBOARD_URL}"
          curl -sS -X POST "${DASHBOARD_URL}" \
            -H "Content-Type: application/json" \
            -H "X-API-KEY: ${API_TOKEN}" \
            --data @reports/risk_summary.json \
            || echo "Dashboard push failed (non-fatal)"
        '''
      }
    }

    stage('Quality Gate') {
      when {
        expression { return env.ENFORCE_GATE == 'true' && fileExists(env.SUMMARY_JSON) }
      }
      steps {
        script {
          def scoreStr = sh(
            script: "python3 -c \"import json; print(json.load(open('reports/risk_summary.json'))['score'])\"",
            returnStdout: true
          ).trim()

          // Convert to number safely
          def totalScore = scoreStr as BigDecimal
          echo "Total risk score: ${totalScore}"

          // Simple gate: fail if score > MAX_TOTAL_SCORE
          def maxScore = env.MAX_TOTAL_SCORE as BigDecimal
          if (totalScore > maxScore) {
            error("Quality Gate failed: score ${totalScore} > max ${maxScore}")
          } else {
            echo "Quality Gate passed: score ${totalScore} <= max ${maxScore}"
          }
        }
      }
    }
  }

  post {
    always {
      echo "Pipeline completed."
    }
  }
}
