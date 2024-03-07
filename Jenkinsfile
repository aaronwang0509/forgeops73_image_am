pipeline {
    agent any
    environment {
        DOCKERHUB_CREDENTIALS_ID = 'DOCKERHUB_CREDENTIALS_ID'
        IMAGE_NAME = 'aaronwang0509/am'
        MAJOR_VERSION = '7'
        MINOR_VERSION = '30'
    }
    stages {
        /*
        stage('Build and Push am-empty Image') {
            steps {
                script {
                    def imageName = "${env.IMAGE_NAME}-empty"
                    def fullVersion = "${env.MAJOR_VERSION}.${env.MINOR_VERSION}.${env.BUILD_NUMBER}"
                    dir('am-empty') {
                        docker.build("${imageName}:${fullVersion}")
                        docker.withRegistry('https://index.docker.io/v1/', env.DOCKERHUB_CREDENTIALS_ID) {
                            docker.image("${imageName}:${fullVersion}").push()
                        }
                    }
                }
            }
        }
        */
        stage('Build and Push am-base Image') {
            steps {
                script {
                    def imageName = "${env.IMAGE_NAME}-base"
                    def fullVersion = "${env.MAJOR_VERSION}.${env.MINOR_VERSION}.${env.BUILD_NUMBER}"
                    dir('am-base') {
                        docker.build("${imageName}:${fullVersion}")
                        docker.withRegistry('https://index.docker.io/v1/', env.DOCKERHUB_CREDENTIALS_ID) {
                            docker.image("${imageName}:${fullVersion}").push()
                        }
                    }
                }
            }
        }
        stage('Build and Push am-config-upgrader Image') {
            steps {
                script {
                    def imageName = "${env.IMAGE_NAME}-config-upgrader"
                    def fullVersion = "${env.MAJOR_VERSION}.${env.MINOR_VERSION}.${env.BUILD_NUMBER}"
                    dir('am-config-upgrader') {
                        docker.build("${imageName}:${fullVersion}")
                        docker.withRegistry('https://index.docker.io/v1/', env.DOCKERHUB_CREDENTIALS_ID) {
                            docker.image("${imageName}:${fullVersion}").push()
                        }
                    }
                }
            }
        }
        stage('Build and Push am Image') {
            steps {
                script {
                    def imageName = "${env.IMAGE_NAME}"
                    def fullVersion = "${env.MAJOR_VERSION}.${env.MINOR_VERSION}.${env.BUILD_NUMBER}"
                    dir('am-cdk') {
                        docker.build("${imageName}:${fullVersion}")
                        docker.withRegistry('https://index.docker.io/v1/', env.DOCKERHUB_CREDENTIALS_ID) {
                            docker.image("${imageName}:${fullVersion}").push()
                        }
                    }
                }
            }
        }
        stage('Build and Push am-build Image') {
            steps {
                script {
                    def imageName = "${env.IMAGE_NAME}-build"
                    def fullVersion = "${env.MAJOR_VERSION}.${env.MINOR_VERSION}.${env.BUILD_NUMBER}"
                    dir('am-build') {
                        docker.build("${imageName}:${fullVersion}")
                        docker.withRegistry('https://index.docker.io/v1/', env.DOCKERHUB_CREDENTIALS_ID) {
                            docker.image("${imageName}:${fullVersion}").push()
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            echo 'Build and push completed.'
        }
    }
}