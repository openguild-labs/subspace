(function() {var implementors = {
"domain_block_preprocessor":[["impl&lt;Block, Executor&gt; <a class=\"trait\" href=\"sp_messenger/trait.MessengerApi.html\" title=\"trait sp_messenger::MessengerApi\">MessengerApi</a>&lt;Block&gt; for <a class=\"struct\" href=\"domain_block_preprocessor/stateless_runtime/struct.StatelessRuntime.html\" title=\"struct domain_block_preprocessor::stateless_runtime::StatelessRuntime\">StatelessRuntime</a>&lt;Block, Executor&gt;<div class=\"where\">where\n    Block: BlockT,\n    NumberFor&lt;Block&gt;: Codec,\n    Executor: CodeExecutor + RuntimeVersionOf,</div>"]],
"evm_domain_runtime":[["impl&lt;__SrApiBlock__: BlockT + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>, RuntimeApiImplCall: CallApiAt&lt;__SrApiBlock__&gt; + 'static&gt; <a class=\"trait\" href=\"sp_messenger/trait.MessengerApi.html\" title=\"trait sp_messenger::MessengerApi\">MessengerApi</a>&lt;__SrApiBlock__&gt; for <a class=\"struct\" href=\"evm_domain_runtime/struct.RuntimeApiImpl.html\" title=\"struct evm_domain_runtime::RuntimeApiImpl\">RuntimeApiImpl</a>&lt;__SrApiBlock__, RuntimeApiImplCall&gt;<div class=\"where\">where\n    RuntimeApiImplCall::StateBackend: StateBackend&lt;HashingFor&lt;__SrApiBlock__&gt;&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'static RuntimeApiImplCall</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"type\" href=\"sp_messenger/messages/type.MessageKey.html\" title=\"type sp_messenger::messages::MessageKey\">MessageKey</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"sp_domains/struct.DomainAllowlistUpdates.html\" title=\"struct sp_domains::DomainAllowlistUpdates\">DomainAllowlistUpdates</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    __SrApiBlock__::Header: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,</div>"]],
"evm_domain_test_runtime":[["impl&lt;__SrApiBlock__: BlockT + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>, RuntimeApiImplCall: CallApiAt&lt;__SrApiBlock__&gt; + 'static&gt; <a class=\"trait\" href=\"sp_messenger/trait.MessengerApi.html\" title=\"trait sp_messenger::MessengerApi\">MessengerApi</a>&lt;__SrApiBlock__&gt; for <a class=\"struct\" href=\"evm_domain_test_runtime/struct.RuntimeApiImpl.html\" title=\"struct evm_domain_test_runtime::RuntimeApiImpl\">RuntimeApiImpl</a>&lt;__SrApiBlock__, RuntimeApiImplCall&gt;<div class=\"where\">where\n    RuntimeApiImplCall::StateBackend: StateBackend&lt;HashingFor&lt;__SrApiBlock__&gt;&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'static RuntimeApiImplCall</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"type\" href=\"sp_messenger/messages/type.MessageKey.html\" title=\"type sp_messenger::messages::MessageKey\">MessageKey</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"sp_domains/struct.DomainAllowlistUpdates.html\" title=\"struct sp_domains::DomainAllowlistUpdates\">DomainAllowlistUpdates</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    __SrApiBlock__::Header: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,</div>"]],
"sp_messenger_host_functions":[],
"subspace_runtime":[["impl&lt;__SrApiBlock__: BlockT + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>, RuntimeApiImplCall: CallApiAt&lt;__SrApiBlock__&gt; + 'static&gt; <a class=\"trait\" href=\"sp_messenger/trait.MessengerApi.html\" title=\"trait sp_messenger::MessengerApi\">MessengerApi</a>&lt;__SrApiBlock__&gt; for <a class=\"struct\" href=\"subspace_runtime/struct.RuntimeApiImpl.html\" title=\"struct subspace_runtime::RuntimeApiImpl\">RuntimeApiImpl</a>&lt;__SrApiBlock__, RuntimeApiImplCall&gt;<div class=\"where\">where\n    RuntimeApiImplCall::StateBackend: StateBackend&lt;HashingFor&lt;__SrApiBlock__&gt;&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'static RuntimeApiImplCall</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"type\" href=\"sp_messenger/messages/type.MessageKey.html\" title=\"type sp_messenger::messages::MessageKey\">MessageKey</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"sp_domains/struct.DomainAllowlistUpdates.html\" title=\"struct sp_domains::DomainAllowlistUpdates\">DomainAllowlistUpdates</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    __SrApiBlock__::Header: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,</div>"]],
"subspace_test_runtime":[["impl&lt;__SrApiBlock__: BlockT + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>, RuntimeApiImplCall: CallApiAt&lt;__SrApiBlock__&gt; + 'static&gt; <a class=\"trait\" href=\"sp_messenger/trait.MessengerApi.html\" title=\"trait sp_messenger::MessengerApi\">MessengerApi</a>&lt;__SrApiBlock__&gt; for <a class=\"struct\" href=\"subspace_test_runtime/struct.RuntimeApiImpl.html\" title=\"struct subspace_test_runtime::RuntimeApiImpl\">RuntimeApiImpl</a>&lt;__SrApiBlock__, RuntimeApiImplCall&gt;<div class=\"where\">where\n    RuntimeApiImplCall::StateBackend: StateBackend&lt;HashingFor&lt;__SrApiBlock__&gt;&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'static RuntimeApiImplCall</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"type\" href=\"sp_messenger/messages/type.MessageKey.html\" title=\"type sp_messenger::messages::MessageKey\">MessageKey</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"sp_domains/struct.DomainAllowlistUpdates.html\" title=\"struct sp_domains::DomainAllowlistUpdates\">DomainAllowlistUpdates</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,\n    __SrApiBlock__::Header: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.UnwindSafe.html\" title=\"trait core::panic::unwind_safe::UnwindSafe\">UnwindSafe</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a>,</div>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()