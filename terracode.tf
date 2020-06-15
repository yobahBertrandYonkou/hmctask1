provider "aws" {
region = "ap-south-1"
profile = "bmbterra"
}

/*=============================================================================================*/

//generates keys
resource "tls_private_key" "terrakey" {
algorithm = "RSA"
}

//stores private key to a file
resource "local_file" "private_key_file" {
depends_on = [ "tls_private_key.terrakey" ]

content     = tls_private_key.terrakey.private_key_pem
filename = "webserver_key.pem"
}

//creates a key pair from the above generated key
resource "aws_key_pair" "webkey" {
key_name = "webserver_key"
public_key = tls_private_key.terrakey.public_key_openssh
}


/*=============================================================================================*/

//creates a security group that allows ssh and http ports for inbound traffic
//and all outbound traffics
resource "aws_security_group" "http_ssh" {
name = "http_sshd"
description = "Allows ssh and http"
vpc_id = "vpc-fe697596"

egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

ingress {
from_port = 80
to_port = 80
protocol = "tcp"
cidr_blocks = ["0.0.0.0/0"]
}

ingress {
from_port = 22
to_port = 22
protocol = "tcp"
cidr_blocks = ["0.0.0.0/0"]
}

tags = {
Name = "HTTP_SSH"
}
}


/*=============================================================================================*/

//creates a t2.micro instance, installs required softwares and starts some httpd service

resource "aws_instance" "myos1" {
depends_on = [ aws_key_pair.webkey, aws_security_group.http_ssh ]
instance_type = "t2.micro"
key_name = aws_key_pair.webkey.key_name
security_groups = [aws_security_group.http_ssh.name]
ami = "ami-0447a12f28fddb066"

//connects to instance via ssh
connection {
type = "ssh"
user = "ec2-user"
host = aws_instance.myos1.public_ip
private_key = file("/root/terrafolder/${local_file.private_key_file.filename}")
}

provisioner "remote-exec" {
inline = [
"sudo yum install git -y",
"sudo yum install httpd -y",
"sudo yum install php -y",
"sudo systemctl start httpd",
"sudo systemctl enable httpd"
]
}

tags = {
Name = "webserver"
}
}


/*=============================================================================================*/

//creates a volume
resource "aws_ebs_volume" "webvolume" {
availability_zone = aws_instance.myos1.availability_zone
size = 1

tags = {
Name = "webhd"
}
}


/*=============================================================================================*/

//attaches the volume created above to the instance above
resource "aws_volume_attachment" "webvol_att" {
depends_on = [ aws_instance.myos1, aws_ebs_volume.webvolume ]
device_name = "/dev/sdh"
instance_id = aws_instance.myos1.id
volume_id = aws_ebs_volume.webvolume.id
force_detach = true

//connects to instance
connection {
type = "ssh"
user = "ec2-user"
host = aws_instance.myos1.public_ip
private_key = file("/root/terrafolder/${local_file.private_key_file.filename}")
}

//mounts attached volume
provisioner "remote-exec" {
inline = [
"sudo mkfs.ext4 /dev/xvdh",
"sudo mount /dev/xvdh /var/www/html",
"sudo rm -rf /var/www/html/*",
"sudo git clone --single-branch --branch master https://github.com/yobahBertrandYonkou/hmctask1.git  /var/www/html"
]
}
}

/*=============================================================================================*/

//creates an s3 bucket
resource "aws_s3_bucket" "cf_bucket" {
  bucket = "bmbvfx"
  acl    = "public-read"

  tags = {
    Name = "cloudF_bucket"
  }
}



/*=============================================================================================*/


//uploads all images to s3 bucket
resource "aws_s3_bucket_object" "upload_images" {
depends_on = [ aws_s3_bucket.cf_bucket ]
  for_each = fileset("/root/terrafolder/static_files/", "**/**.jpg")
  force_destroy = true
  content_type = "image/jpg"
  bucket = aws_s3_bucket.cf_bucket.bucket
  key    = each.value
  source = "/root/terrafolder/static_files/${each.value}"
}



/*=============================================================================================*/


//sets s3 bucket id to be used when creating a cloudFront destribution
locals {
  s3_origin_id = "S3-bmbvfx"
}

//creates an origin acess indetity for cf
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "let_me_pass"
}



/*=============================================================================================*/


//creates a cloudFront distribution
resource "aws_cloudfront_distribution" "cloud_front_dist" {
depends_on = [ aws_s3_bucket.cf_bucket ]
  origin {
    domain_name = "${aws_s3_bucket.cf_bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"

    
      s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }


  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["DE"]
    }
  }

  tags = {
    env = "testing"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}



/*=============================================================================================*/


//updating bucket policy
data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.cf_bucket.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.cf_bucket.arn}"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}

resource "aws_s3_bucket_policy" "bmbvfx_policy" {
  depends_on = [ aws_s3_bucket.cf_bucket, aws_cloudfront_distribution.cloud_front_dist ]
  bucket = "${aws_s3_bucket.cf_bucket.id}"
  policy = "${data.aws_iam_policy_document.s3_policy.json}"
}


/*=============================================================================================*/
variable "default_url" {
default = "cloudFrontUrl"
}

//updating code in /var/www/html with CF Url
resource "null_resource" "set_cf_url" {
depends_on = [ aws_cloudfront_distribution.cloud_front_dist ]
connection {
type = "ssh"
user = "ec2-user"
host = aws_instance.myos1.public_ip
private_key = file("/root/terrafolder/${local_file.private_key_file.filename}")
}

provisioner "remote-exec" {
inline =[ "sudo sed -i 's/${var.default_url}/${aws_cloudfront_distribution.cloud_front_dist.domain_name}/g' /var/www/html/index.html" ] 
}
}

