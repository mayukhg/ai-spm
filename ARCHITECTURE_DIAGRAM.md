# AWS Architecture Diagram

This diagram illustrates the AWS architecture for the AI Security Posture Management (AI-SPM) platform, as defined by the CloudFormation template.

## Diagram

To view the diagram, use a Markdown preview tool with Mermaid support, or paste the code block below into the Mermaid Live Editor (https://mermaid.live).

```mermaid
graph TD
    subgraph User Facing
        User["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/user.svg' width='40' height='40' /><br/>User"]
    end

    subgraph CDN Layer
        CloudFront["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> CloudFront Distribution"]
    end

    subgraph Application Load Balancer Layer
        ALB["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> Application Load Balancer (ALB)"]
    end

    subgraph Frontend Hosting Layer [AWS S3]
        S3_Bucket["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> S3 Bucket (Frontend Assets)"]
    end

    subgraph Backend Compute Layer [AWS ECS on Fargate in Private Subnets]
        ECS_Service["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> ECS Service (Fargate Tasks)"]
        AppContainer["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/box.svg' width='20' height='20' /><br/>Node.js App Container"]
    end

    ECS_Service --> AppContainer

    subgraph Database Layer [AWS RDS in Private Subnets]
        RDS_PostgreSQL["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> RDS PostgreSQL"]
    end

    subgraph Networking [AWS VPC]
        PublicSubnets["Public Subnets"]
        PrivateSubnets["Private Subnets"]
        NAT_Gateway["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> NAT Gateway"]
        IGW["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> Internet Gateway"]
    end

    ALB --> PublicSubnets
    NAT_Gateway --> PublicSubnets
    PublicSubnets --> IGW
    ECS_Service --> PrivateSubnets
    RDS_PostgreSQL --> PrivateSubnets
    PrivateSubnets --> NAT_Gateway


    subgraph Security & Management
        IAM["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> IAM (Roles & Policies)"]
        SecretsManager["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> Secrets Manager"]
        CloudWatchLogs["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> CloudWatch Logs"]
        ECR["<img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/aws.svg' width='20' height='20' /> ECR (Docker Images)"]
    end

    %% Connections %%
    User -- "HTTPS (yourapp.com)" --> CloudFront

    CloudFront -- "Static Assets (Default Behavior)<br/>OAC" --> S3_Bucket
    CloudFront -- "API Requests (/api/*)" --> ALB

    ALB -- "HTTP/HTTPS" --> ECS_Service

    AppContainer -- "SQL over TCP/IP" --> RDS_PostgreSQL
    AppContainer -- "Reads Secrets" --> SecretsManager
    AppContainer -- "Writes Logs" --> CloudWatchLogs

    ECS_Service -- "Pulls Image" --> ECR
    ECS_Service -- "Uses IAM Roles" --> IAM
    RDS_PostgreSQL -- "Uses IAM (for auth, optional)" --> IAM
    SecretsManager -- "Managed by IAM" --> IAM


    %% External Services (Example)
    subgraph ExternalServices
        WizAPI["Wiz API (Optional)"]
    end
    AppContainer -- "HTTPS (Outbound via NAT)" --> WizAPI


    %% Style Definitions (Optional, for better rendering if supported)
    classDef cdn fill:#FF9900,stroke:#333,stroke-width:2px;
    classDef alb fill:#FF9900,stroke:#333,stroke-width:2px;
    classDef s3 fill:#5A30B5,stroke:#333,stroke-width:2px;
    classDef ecs fill:#232F3E,stroke:#FF9900,stroke-width:2px,color:#fff;
    classDef rds fill:#5A30B5,stroke:#333,stroke-width:2px;
    classDef network fill:#D1E7DD,stroke:#333,stroke-width:1px;
    classDef security fill:#F8F9FA,stroke:#333,stroke-width:1px;

    class CloudFront cdn;
    class ALB alb;
    class S3_Bucket s3;
    class ECS_Service ecs;
    class AppContainer ecs;
    class RDS_PostgreSQL rds;
    class NAT_Gateway,IGW,PublicSubnets,PrivateSubnets network;
    class IAM,SecretsManager,CloudWatchLogs,ECR security;
```
