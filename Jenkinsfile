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

    // Post-build Actions
    post { 
        always { 
            echo 'Sending notification to your email...'
            emailext to: 'koirala.prayag111@gmail.com',
                subject: "Job '${JOB_NAME}' '${BUILD_NUMBER}' is being Built",
                body: "Please go to ${BUILD_URL} and verify the build",
                mimeType: 'text/plain'
        }
        success {
            echo 'Sending success email notification...'
            emailext subject: 'Net Monitor Build Successful',
                body: 'The Net Monitor build is successful. You can open the dashboard on localhost:5601.',
                to: 'koirala.prayag111@gmail.com',
                mimeType: 'text/html',
                replyTo: '',
                from: ''
        }
        failure {
            echo 'Sending retry email notification...'
            emailext subject: 'Net Monitor Build Failed',
                body: 'The Net Monitor build has failed. Please retry the build.',
                to: 'koirala.prayag111@gmail.com',
                mimeType: 'text/html',
                replyTo: '',
                from: ''
        }
    }
}
