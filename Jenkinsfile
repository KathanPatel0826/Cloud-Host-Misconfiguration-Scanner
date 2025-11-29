pipeline {
  agent any

  environment {
    // Risk policy
    MAX_TOTAL_SCORE = '80'
    MIN_PASS_GRADE  = 'C'
    ENFORCE_GATE    = 'true'   // set to 'false' if you want to bypass the gate

    // Paths
    NORMALIZED_JSON = 'out/normalized_findings.json'
    OUT_DIR         = 'out'
    REPORT_HTML     = 'out/risk_report.html'
    REPORT_PDF      = 'out/risk_report.pdf'
  }

  stages {

    // One-time cleanup for old job parameters
    stage('Init (clear old params)') {
      steps {
        script {
          properties([])   // ensures job is no longer parameterized
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
          pip install jinja2 weasyprint || true
        '''
      }
    }

    stage('Security Scan + Normalize') {
      steps {
        sh '''
          . .venv/bin/activate

          # TODO: keep your existing commands here.
          # Example placeholder (replace with your real scan + normalize steps):
          # python3 main.py --out out/raw_results
          # python3 normalize.py --in out/raw_results --out out

          # For your current setup, just leave whatever you already had in this stage.
        '''
      }
    }

    stage('Precheck Inputs') {
      steps {
        sh '''
          if [ ! -f "$NORMALIZED_JSON" ]; then
            echo "ERROR: Missing $NORMALIZED_JSON. Ensure your normalization stage produced it."
            ls -R
            exit 2
          fi
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          . .venv/bin/activate
          python3 score_and_report.py --in "$NORMALIZED_JSON" --out "$OUT_DIR" --pdf || \
          python3 score_and_report.py --in "$NORMALIZED_JSON" --out "$OUT_DIR"
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'out/risk_report.*', fingerprint: true
        publishHTML(target: [
          reportDir: 'out',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report',
          keepAll: true,
          alwaysLinkToLastBuild: true,
          allowMissing: false
        ])
      }
    }

    // 🔄 NEW: push risk_summary.json to the Flask backend
    stage('Push to Dashboard') {
      when {
        expression { return fileExists('out/risk_summary.json') }
      }
      steps {
        script {
          def backendUrl = 'http://192.168.31.128:8088/ingest'   // use the IP shown by server.py
          def apiToken   = 'my-super-secret-token-123'           // same as API_TOKEN in server.py

          sh """
            python3 - << 'EOF'
import json, os

summary_path = 'out/risk_summary.json'
with open(summary_path) as f:
    data = json.load(f)

data['build_id'] = os.environ.get('BUILD_NUMBER')
data['artifact_url'] = os.environ.get('BUILD_URL') + 'artifact/out/risk_report.html'

out_path = 'out/risk_summary_with_meta.json'
with open(out_path, 'w') as f:
    json.dump(data, f)
print('Wrote', out_path)
EOF

            curl -sS -X POST ${backendUrl} \
              -H 'Content-Type: application/json' \
              -H 'X-API-KEY: ${apiToken}' \
              --data @out/risk_summary_with_meta.json || echo "Dashboard push failed (non-fatal)"
          """
        }
      }
    }

    stage('Quality Gate') {
      when { expression { return env.ENFORCE_GATE == 'true' } }
      steps {
        script {
          def totalScore = sh(
            script: "grep -o 'Total Risk Score</div><div><b>[^<]*' ${env.REPORT_HTML} | sed 's/.*<b>//'",
            returnStdout: true
          ).trim()

          def grade = sh(
            script: "grep -o 'Risk Grade</div><div class=\"grade\">[^<]*' ${env.REPORT_HTML} | sed 's/.*grade\">//'",
            returnStdout: true
          ).trim()

          echo "Quality Gate => totalScore=${totalScore}, grade=${grade}"

          def fail = false
          if (totalScore?.isNumber() && totalScore.toFloat() > env.MAX_TOTAL_SCORE.toFloat()) {
            echo "Gate breach: total score ${totalScore} > ${env.MAX_TOTAL_SCORE}"
            fail = true
          }
          def rank = ['A':5,'B':4,'C':3,'D':2,'F':1]
          if (rank.get(grade,1) < rank.get(env.MIN_PASS_GRADE,3)) {
            echo "Gate breach: grade ${grade} worse than ${env.MIN_PASS_GRADE}"
            fail = true
          }

          if (fail) {
            error "Quality Gate failed."
          } else {
            echo "Quality Gate passed."
          }
        }
      }
    }
  }

  post {
    always {
      echo 'Pipeline finished (reports archived, pushed to dashboard, and gate evaluated).'
    }
  }
}
