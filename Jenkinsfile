pipeline {
    agent any

    stages {
        // Stage 1: Clean Up
        stage('Clean Up') {
            steps {
                echo 'Cleaning up...'
                // Remove previous Docker images and containers (ignore errors if they don't exist)
                sh 'docker rmi -f harbor.registry.local/devops-mynetmon/my-net-mon:v1.$((BUILD_NUMBER - 1)) || true'
                sh 'docker container stop my-net-mon || true'
                sh 'docker container rm my-net-mon || true'
                sh 'docker compose -f ./docker-compose/docker-compose.yml down || true'
            }
        }

        // Stage 2: Build Docker Image
        stage('Build') {
            steps {
                echo 'Building Docker image...'
                // Build a new Docker image
                sh 'docker build -t harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER ./my-net-mon-docker-image/'
            }
        }

        // Stage 3: Deploy Containers
        stage('Deploy') {
            steps {
                echo 'Deploying containers...'
                // Pull necessary Docker images
                sh 'docker pull harbor.registry.local/devops-mynetmon/openserach'
                sh 'docker pull harbor.registry.local/devops-mynetmon/openserach-dashboards'
                sh 'docker pull harbor.registry.local/devops-mynetmon/logstash'

                // Start Docker containers using Docker Compose
                sh 'docker compose -f ./docker-compose/docker-compose.yml up -d'

                // Run a Docker container with a specific name and volume
                sh 'docker run -itd --name my-net-mon -v /home/nova056/logfiles:/opt/logfiles harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'
            }
        }

        // Stage 4: Push Docker Image
        stage('Push') {
            steps {
                echo 'Pushing Docker image...'
                // Push the newly built Docker image to the registry
                sh 'docker push harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'
            }
        }
    }

     post { 
        always { 
            mail to: 'imroot056@gmail.com',
            subject: "Job '${JOB_NAME}' build number #${BUILD_NUMBER} is being build",
            body: "Please go to ${BUILD_URL} and verify the build"
        }
        success {
            mail bcc: '', body: """Hi Team,

Build #$BUILD_NUMBER is successful, please go through the url

$BUILD_URL

and verify the details.

Regards,
DevOps Team""", cc: '', from: '', replyTo: '', subject: 'BUILD SUCCESS NOTIFICATION', to: 'imroot056@gmail.com'
        }
        failure {
            mail bcc: '', body: """Hi Team,
            
Build #$BUILD_NUMBER is unsuccessful, please go through the url

$BUILD_URL

and verify the details.

Regards,
DevOps Team""", cc: '', from: '', replyTo: '', subject: 'BUILD FAILED NOTIFICATION', to: 'imroot056@gmail.com'
        }
    }

}
