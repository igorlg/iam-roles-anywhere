"""Tests for lib/storage/s3.py - S3 storage operations with moto."""

import pytest
from moto import mock_aws

from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.lib.storage.s3 import delete_object, object_exists, read_object, write_object


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def s3_client(aws_credentials: None):
    """Create mocked S3 client."""
    import boto3

    with mock_aws():
        client = boto3.client("s3", region_name="ap-southeast-2")
        yield client


@pytest.fixture
def bucket_with_object(s3_client):
    """Create a bucket with a test object."""
    bucket = "test-bucket"
    key = "test-key.txt"
    content = "Hello, World!"

    s3_client.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"}
    )
    s3_client.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))

    return s3_client, bucket, key, content


class TestReadObject:
    """Tests for read_object function."""

    def test_read_existing_object(self, bucket_with_object) -> None:
        s3, bucket, key, content = bucket_with_object

        result = read_object(s3, bucket, key)

        assert isinstance(result, Ok)
        assert result.value == content

    def test_read_nonexistent_object(self, bucket_with_object) -> None:
        s3, bucket, _, _ = bucket_with_object

        result = read_object(s3, bucket, "nonexistent-key")

        assert isinstance(result, Err)
        assert result.error.bucket == bucket
        assert result.error.key == "nonexistent-key"
        assert "not found" in result.error.reason.lower()

    def test_read_from_nonexistent_bucket(self, s3_client) -> None:
        result = read_object(s3_client, "nonexistent-bucket", "any-key")

        assert isinstance(result, Err)
        assert result.error.bucket == "nonexistent-bucket"


class TestWriteObject:
    """Tests for write_object function."""

    def test_write_new_object(self, bucket_with_object) -> None:
        s3, bucket, _, _ = bucket_with_object
        new_key = "new-key.txt"
        new_content = "New content"

        result = write_object(s3, bucket, new_key, new_content)

        assert isinstance(result, Ok)
        assert result.value is None

        # Verify it was written
        response = s3.get_object(Bucket=bucket, Key=new_key)
        assert response["Body"].read().decode("utf-8") == new_content

    def test_write_overwrites_existing(self, bucket_with_object) -> None:
        s3, bucket, key, _ = bucket_with_object
        new_content = "Updated content"

        result = write_object(s3, bucket, key, new_content)

        assert isinstance(result, Ok)

        # Verify it was overwritten
        response = s3.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read().decode("utf-8") == new_content

    def test_write_to_nonexistent_bucket(self, s3_client) -> None:
        result = write_object(s3_client, "nonexistent-bucket", "any-key", "content")

        assert isinstance(result, Err)
        assert result.error.bucket == "nonexistent-bucket"

    def test_write_unicode_content(self, bucket_with_object) -> None:
        s3, bucket, _, _ = bucket_with_object
        key = "unicode.txt"
        content = "Hello, World!"

        result = write_object(s3, bucket, key, content)

        assert isinstance(result, Ok)

        # Verify encoding
        response = s3.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read().decode("utf-8") == content


class TestDeleteObject:
    """Tests for delete_object function."""

    def test_delete_existing_object(self, bucket_with_object) -> None:
        s3, bucket, key, _ = bucket_with_object

        result = delete_object(s3, bucket, key)

        assert isinstance(result, Ok)

        # Verify it's gone
        assert object_exists(s3, bucket, key) is False

    def test_delete_nonexistent_object_succeeds(self, bucket_with_object) -> None:
        """S3 delete is idempotent - deleting non-existent key succeeds."""
        s3, bucket, _, _ = bucket_with_object

        result = delete_object(s3, bucket, "nonexistent-key")

        # S3 doesn't error on deleting non-existent keys
        assert isinstance(result, Ok)


class TestObjectExists:
    """Tests for object_exists function."""

    def test_exists_returns_true_for_existing(self, bucket_with_object) -> None:
        s3, bucket, key, _ = bucket_with_object

        assert object_exists(s3, bucket, key) is True

    def test_exists_returns_false_for_nonexistent(self, bucket_with_object) -> None:
        s3, bucket, _, _ = bucket_with_object

        assert object_exists(s3, bucket, "nonexistent-key") is False

    def test_exists_returns_false_for_nonexistent_bucket(self, s3_client) -> None:
        assert object_exists(s3_client, "nonexistent-bucket", "any-key") is False
