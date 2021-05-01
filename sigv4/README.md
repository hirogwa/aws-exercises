sigv4
---
SDKなしでAWS使うの難しくない？

https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

# Set credentials
```
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE
export AWS_SECRET_ACCESS_KEY=secretExample
export AWS_SESSION_TOKEN=IQoExample
```

# With query parameters
IAM

```
$ python sigv4.py iam ListUsers us-east-1 -qs --content-type application/x-amz-json-1.1

...
2021-05-01 13:11:02,342  INFO <ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListUsersResult>
    <IsTruncated>false</IsTruncated>
    <Users>
      <member>
        <Path>/</Path>
        <PasswordLastUsed>2021-05-01T19:39:10Z</PasswordLastUsed>
        <Arn>arn:aws:iam::123456789012:user/admin</Arn>
        <UserName>admin</UserName>
        <UserId>AIDAVI363QCFCIEXAMPLE</UserId>
        <CreateDate>2020-04-18T20:48:29Z</CreateDate>
      </member>
    </Users>
  </ListUsersResult>
  <ResponseMetadata>
    <RequestId>83d373d1-ed91-46c0-a4b5-96ab560e6d78</RequestId>
  </ResponseMetadata>
</ListUsersResponse>
```

STS

```
$ python sigv4.py sts GetAccessKeyInfo us-east-1 --params AccessKeyId=ASIAVI363QCFDEXAMPLE -qs --content-type application/x-amz-json-1.1

...
2021-05-01 13:09:08,006  INFO <GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetAccessKeyInfoResult>
    <Account>123456789012</Account>
  </GetAccessKeyInfoResult>
  <ResponseMetadata>
    <RequestId>31be9da8-5a8c-42c5-8f66-e70215d5a01c</RequestId>
  </ResponseMetadata>
</GetAccessKeyInfoResponse>
```

# Without query parameters
IAM

```
$ python sigv4.py iam ListUsers us-east-1 --content-type application/x-www-form-urlencoded

(same response as above)
```

STS

```
$ python sigv4.py sts GetAccessKeyInfo us-east-1 --params AccessKeyId=ASIAVI363QCFDEXAMPLE --content-type application/x-www-form-urlencoded

(same response as above)
```
