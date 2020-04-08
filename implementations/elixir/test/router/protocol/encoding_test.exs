defmodule Ockam.Router.Protocol.Encoding.Test do
  use ExUnit.Case, async: true
  require Logger

  alias Ockam.Router.Protocol.Message
  alias Ockam.Router.Protocol.Encoding

  test "ping" do
    ping = %Message.Ping{}
    opts = %{}

    assert {:ok, encoded} = Encoding.encode(ping, opts)
    assert {:ok, ^ping, <<>>} = Encoding.decode(encoded, opts)
  end

  test "pong" do
    pong = %Message.Pong{}
    opts = %{}

    assert {:ok, encoded} = Encoding.encode(pong, opts)
    assert {:ok, ^pong, <<>>} = Encoding.decode(encoded, opts)
  end

  test "payloads" do
    payload = %Message.Payload{data: "hello"}
    opts = %{}

    assert {:ok, encoded} = Encoding.encode(payload, opts)
    assert {:ok, ^payload, <<>>} = Encoding.decode(encoded, opts)

    tag = String.duplicate("t", 16)
    encrypted_payload = %Message.EncryptedPayload{data: "hello", tag: tag}

    assert {:ok, encoded} = Encoding.encode(encrypted_payload, opts)
    assert {:ok, ^encrypted_payload, <<>>} = Encoding.decode(encoded, opts)
  end

  test "connect" do
    connect = %Message.Connect{
      options: [
        %Message.Connect.Option{name: "foo", value: "bar"},
        %Message.Connect.Option{name: "baz", value: "qux"}
      ]
    }

    opts = %{}

    assert {:ok, encoded} = Encoding.encode(connect, opts)
    assert {:ok, ^connect, <<>>} = Encoding.decode(encoded, opts)
  end
end
