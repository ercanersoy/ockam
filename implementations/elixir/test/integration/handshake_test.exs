defmodule Ockam.Integration.Handshake.Test do
  use ExUnit.Case, async: false
  require Logger

  alias Ockam.Channel
  alias Ockam.Transport.Address
  alias Ockam.Transport.Socket
  alias Ockam.Vault.KeyPair

  setup context do
    if transport = context[:transport] do
      name = Map.fetch!(context, :transport_name)
      meta = [name: name]
      config = Map.get(context, :transport_config, [])
      pid = start_supervised!({transport, [meta, config]})
      {:ok, [pid: pid, config: config]}
    else
      {:ok, []}
    end
  end

  @tag transport: Ockam.Transport.TCP
  @tag transport_name: :tcp_4000
  @tag transport_config: [listen_address: "0.0.0.0", listen_port: 4000]
  @tag capture_log: false
  test "with C implementation as initiator", %{config: _config} do
    assert {:ok, _} = invoke_test_executable!()
  end


  @tag initiator: true
  @tag listen_port: 4000
  test "with C implementation as responder", %{listen_port: port} do
    # TODO: Start server first
    # assert {:ok, _} = invoke_test_executable!([...])

    {:ok, addr} = Address.new(:inet, :loopback, port)
    socket = Socket.new(:client, addr)

    s = KeyPair.new(:x25519)
    e = KeyPair.new(:x25519)
    rs = KeyPair.new(:x25519)
    re = KeyPair.new(:x25519)

    handshake_opts = %{protocol: "Noise_XX_25519_AESGCM_SHA256", s: s, e: e, rs: rs, re: re}
    assert {:ok, handshake} = Channel.handshake(:initiator, handshake_opts)
    assert {:ok, transport} = Socket.open(socket)
    assert {:ok, _chan, transport} = Channel.negotiate_secure_channel(handshake, transport)
    assert {:ok, _} = Socket.close(transport)
  end

  defp invoke_test_executable!(args \\ []) when is_list(args) do
    init_dir = Path.expand(Path.join([__DIR__, "..", "..", "..", "c", "_build"]))
    init_cmd = Path.join([init_dir, "Debug", "tests", "ockam_key_agreement_tests_xx_integration"])
    {output, status} = System.cmd(init_cmd, args, cd: init_dir, stderr_to_stdout: true)

    if status != 0 do
      Logger.warn("Captured Output:\n" <> output)
      {:error, status}
    else
      {:ok, output}
    end
  end
end
