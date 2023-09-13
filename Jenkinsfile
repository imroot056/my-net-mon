pipeline {
    agent any

    stages {
        stage('Clean Up') {
            steps {
                sh 'docker rmi -f harbor.registry.local/devops-mynetmon/my-net-mon:v1.$((BUILD_NUMBER - 1)) || true'
                sh 'docker container stop my-net-mon || true'
                sh 'docker container rm my-net-mon || true'
                sh 'docker compose -f ./docker-compose/docker-compose.yml down || true'
            }
        }

        stage('Build') {
            steps {
                sh 'docker build -t harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER ./my-net-mon-docker-image/'
            }
        }

        stage('Deploy') {
            steps {
                sh 'docker pull harbor.registry.local/devops-mynetmon/openserach'
                sh 'docker pull harbor.registry.local/devops-mynetmon/openserach-dashboards'
                sh 'docker pull harbor.registry.local/devops-mynetmon/logstash'
                sh 'docker compose -f ./docker-compose/docker-compose.yml up -d'
                sh 'docker run -itd --name my-net-mon -v /home/nova056/logfiles:/opt/logfiles harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'
            }
        }

        stage('Push') {
            steps {
                sh 'docker push harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'
            }
        }
    }
}
