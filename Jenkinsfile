pipeline {
  agent any

  environment {
    MAX_TOTAL_SCORE = '80'   
    MIN_PASS_GRADE  = 'C'    
    ENFORCE_GATE    = 'true' 

    NORMALIZED_JSON = 'out/normalized_findings.json'
    OUT_DIR         = 'out'
    REPORT_HTML     = 'out/risk_report.html'
    REPORT_PDF      = 'out/risk_report.pdf'
  }

  stages {

    // Run ONCE to clear old, persisted job parameters that cause "Build with Parameters".
    // After it runs successfully, you can delete this stage from the Jenkinsfile.
    stage('Init (clear old params)') {
      steps {
        script {
          properties([]) // removes previously set parameters on the job
          echo 'Cleared leftover job parameters.'
        }
      }
    }

    stage('Checkout') {
      steps { checkout scm }
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

    // If your pipeline already produces out/normalized_findings.json earlier, keep that stage.
    // Otherwise ensure the file exists before Risk Report runs.
    stage('Precheck Inputs') {
      steps {
        sh '''
          if [ ! -f "$NORMALIZED_JSON" ]; then
            echo "ERROR: Missing $NORMALIZED_JSON. Ensure your normalization stage produced it."
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

    stage('Quality Gate') {
      when { expression { return env.ENFORCE_GATE == 'true' } }
      steps {
        script {
          // Parse totals from the HTML (dependency-free)
          def totalScore = sh(
            script: "grep -o 'Total Risk Score</div><div><b>[^<]*' ${env.REPORT_HTML} | sed 's/.*<b>//'",
            returnStdout: true
          ).trim()

          def grade = sh(
            script: "grep -o 'Risk Grade</div><div class=\"grade\">[^<]*' ${env.REPORT_HTML} | sed 's/.*grade\">//'",
            returnStdout: true
          ).trim()

          echo "Quality Gate => totalScore=${totalScore}, grade=${grade}"

          // Evaluate policy
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
      echo 'Pipeline finished (reports archived & published).'
    }
  }
}
