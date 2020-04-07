defmodule Ockam.Integration.Handshake.Test do
  use ExUnit.Case, async: false
  require Logger

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
    init_dir = Path.expand(Path.join([__DIR__, "..", "..", "..", "c", "_build"]))
    init_cmd = Path.join([init_dir, "Debug", "tests", "ockam_key_agreement_tests_xx_integration"])
    {output, status} = System.cmd(init_cmd, [], cd: init_dir, stderr_to_stdout: true)

    if status != 0 do
      Logger.warn("Captured Output:\n" <> output)
    end

    assert status == 0
  end
end
