(function() {var type_impls = {
"subspace_service":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-BasicPoolWrapper%3CBlock,+PoolApi%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#264-304\">source</a><a href=\"#impl-BasicPoolWrapper%3CBlock,+PoolApi%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Block, PoolApi&gt; <a class=\"struct\" href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html\" title=\"struct subspace_service::transaction_pool::BasicPoolWrapper\">BasicPoolWrapper</a>&lt;Block, PoolApi&gt;<div class=\"where\">where\n    Block: BlockT,\n    PoolApi: ChainApi&lt;Block = Block&gt; + 'static,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.pool\" class=\"method\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#297-299\">source</a><h4 class=\"code-header\">pub fn <a href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html#tymethod.pool\" class=\"fn\">pool</a>(&amp;self) -&gt; &amp;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;Pool&lt;PoolApi&gt;&gt;</h4></section></summary><div class=\"docblock\"><p>Gets shared reference to the underlying pool.</p>\n</div></details><section id=\"method.api\" class=\"method\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#301-303\">source</a><h4 class=\"code-header\">pub fn <a href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html#tymethod.api\" class=\"fn\">api</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;PoolApi</a></h4></section></div></details>",0,"subspace_service::transaction_pool::FullPool"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MaintainedTransactionPool-for-BasicPoolWrapper%3CBlock,+PoolApi%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#443-451\">source</a><a href=\"#impl-MaintainedTransactionPool-for-BasicPoolWrapper%3CBlock,+PoolApi%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Block, PoolApi&gt; MaintainedTransactionPool for <a class=\"struct\" href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html\" title=\"struct subspace_service::transaction_pool::BasicPoolWrapper\">BasicPoolWrapper</a>&lt;Block, PoolApi&gt;<div class=\"where\">where\n    Block: BlockT,\n    PoolApi: ChainApi&lt;Block = Block&gt; + 'static,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.maintain\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#448-450\">source</a><a href=\"#method.maintain\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">maintain</a>&lt;'life0, 'async_trait&gt;(\n    &amp;'life0 self,\n    event: ChainEvent&lt;Self::Block&gt;\n) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/pin/struct.Pin.html\" title=\"struct core::pin::Pin\">Pin</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;dyn <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/future/future/trait.Future.html\" title=\"trait core::future::future::Future\">Future</a>&lt;Output = <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + 'async_trait&gt;&gt;<div class=\"where\">where\n    Self: 'async_trait,\n    'life0: 'async_trait,</div></h4></section></summary><div class='docblock'>Perform maintenance</div></details></div></details>","MaintainedTransactionPool","subspace_service::transaction_pool::FullPool"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-LocalTransactionPool-for-BasicPoolWrapper%3CBlock,+FullChainApiWrapper%3CClient,+Block,+DomainHeader%3E%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#306-366\">source</a><a href=\"#impl-LocalTransactionPool-for-BasicPoolWrapper%3CBlock,+FullChainApiWrapper%3CClient,+Block,+DomainHeader%3E%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Block, Client, DomainHeader&gt; LocalTransactionPool for <a class=\"struct\" href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html\" title=\"struct subspace_service::transaction_pool::BasicPoolWrapper\">BasicPoolWrapper</a>&lt;Block, <a class=\"struct\" href=\"subspace_service/transaction_pool/struct.FullChainApiWrapper.html\" title=\"struct subspace_service::transaction_pool::FullChainApiWrapper\">FullChainApiWrapper</a>&lt;Client, Block, DomainHeader&gt;&gt;<div class=\"where\">where\n    Block: BlockT,\n    &lt;&lt;&lt;Block as BlockT&gt;::Header as HeaderT&gt;::Number as <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryInto.html\" title=\"trait core::convert::TryInto\">TryInto</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryInto.html#associatedtype.Error\" title=\"type core::convert::TryInto::Error\">Error</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,\n    DomainHeader: HeaderT,\n    Client: ProvideRuntimeApi&lt;Block&gt; + AuxStore + BlockBackend&lt;Block&gt; + BlockIdTo&lt;Block&gt; + HeaderBackend&lt;Block&gt; + HeaderMetadata&lt;Block, Error = Error&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + 'static,\n    Client::Api: TaggedTransactionQueue&lt;Block&gt; + <a class=\"trait\" href=\"sp_consensus_subspace/trait.SubspaceApi.html\" title=\"trait sp_consensus_subspace::SubspaceApi\">SubspaceApi</a>&lt;Block, <a class=\"type\" href=\"sp_consensus_subspace/type.FarmerPublicKey.html\" title=\"type sp_consensus_subspace::FarmerPublicKey\">FarmerPublicKey</a>&gt; + <a class=\"trait\" href=\"sp_domains_fraud_proof/trait.FraudProofApi.html\" title=\"trait sp_domains_fraud_proof::FraudProofApi\">FraudProofApi</a>&lt;Block, DomainHeader&gt; + DomainsApi&lt;Block, DomainHeader&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Block\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Block\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Block</a> = Block</h4></section></summary><div class='docblock'>Block type.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Hash\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Hash\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Hash</a> = &lt;&lt;<a class=\"struct\" href=\"subspace_service/transaction_pool/struct.FullChainApiWrapper.html\" title=\"struct subspace_service::transaction_pool::FullChainApiWrapper\">FullChainApiWrapper</a>&lt;Client, Block, DomainHeader&gt; as ChainApi&gt;::Block as Block&gt;::Hash</h4></section></summary><div class='docblock'>Transaction hash type.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Error</a> = &lt;<a class=\"struct\" href=\"subspace_service/transaction_pool/struct.FullChainApiWrapper.html\" title=\"struct subspace_service::transaction_pool::FullChainApiWrapper\">FullChainApiWrapper</a>&lt;Client, Block, DomainHeader&gt; as ChainApi&gt;::Error</h4></section></summary><div class='docblock'>Error type.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.submit_local\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#330-365\">source</a><a href=\"#method.submit_local\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">submit_local</a>(\n    &amp;self,\n    at: Block::Hash,\n    xt: LocalTransactionFor&lt;Self&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::Hash, Self::Error&gt;</h4></section></summary><div class='docblock'>Submits the given local unverified transaction to the pool blocking the\ncurrent thread for any necessary pre-verification.\nNOTE: It MUST NOT be used for transactions that originate from the\nnetwork or RPC, since the validation is performed with\n<code>TransactionSource::Local</code>.</div></details></div></details>","LocalTransactionPool","subspace_service::transaction_pool::FullPool"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TransactionPool-for-BasicPoolWrapper%3CBlock,+PoolApi%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#368-440\">source</a><a href=\"#impl-TransactionPool-for-BasicPoolWrapper%3CBlock,+PoolApi%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Block, PoolApi&gt; TransactionPool for <a class=\"struct\" href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html\" title=\"struct subspace_service::transaction_pool::BasicPoolWrapper\">BasicPoolWrapper</a>&lt;Block, PoolApi&gt;<div class=\"where\">where\n    Block: BlockT,\n    PoolApi: ChainApi&lt;Block = Block&gt; + 'static,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Block\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Block\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Block</a> = Block</h4></section></summary><div class='docblock'>Block type.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Hash\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Hash\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Hash</a> = &lt;&lt;PoolApi as ChainApi&gt;::Block as Block&gt;::Hash</h4></section></summary><div class='docblock'>Transaction hash type.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.InPoolTransaction\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.InPoolTransaction\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">InPoolTransaction</a> = Transaction&lt;&lt;<a class=\"struct\" href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html\" title=\"struct subspace_service::transaction_pool::BasicPoolWrapper\">BasicPoolWrapper</a>&lt;Block, PoolApi&gt; as TransactionPool&gt;::Hash, &lt;&lt;<a class=\"struct\" href=\"subspace_service/transaction_pool/struct.BasicPoolWrapper.html\" title=\"struct subspace_service::transaction_pool::BasicPoolWrapper\">BasicPoolWrapper</a>&lt;Block, PoolApi&gt; as TransactionPool&gt;::Block as Block&gt;::Extrinsic&gt;</h4></section></summary><div class='docblock'>In-pool transaction type.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Error</a> = &lt;PoolApi as ChainApi&gt;::Error</h4></section></summary><div class='docblock'>Error type.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.submit_at\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#378-385\">source</a><a href=\"#method.submit_at\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">submit_at</a>(\n    &amp;self,\n    at: Block::Hash,\n    source: TransactionSource,\n    xts: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;TransactionFor&lt;Self&gt;&gt;\n) -&gt; PoolFuture&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;TxHash&lt;Self&gt;, Self::Error&gt;&gt;, Self::Error&gt;</h4></section></summary><div class='docblock'>Returns a future that imports a bunch of unverified transactions to the pool.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.submit_one\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#387-394\">source</a><a href=\"#method.submit_one\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">submit_one</a>(\n    &amp;self,\n    at: Block::Hash,\n    source: TransactionSource,\n    xt: TransactionFor&lt;Self&gt;\n) -&gt; PoolFuture&lt;TxHash&lt;Self&gt;, Self::Error&gt;</h4></section></summary><div class='docblock'>Returns a future that imports one unverified transaction to the pool.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.submit_and_watch\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#396-403\">source</a><a href=\"#method.submit_and_watch\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">submit_and_watch</a>(\n    &amp;self,\n    at: Block::Hash,\n    source: TransactionSource,\n    xt: TransactionFor&lt;Self&gt;\n) -&gt; PoolFuture&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/pin/struct.Pin.html\" title=\"struct core::pin::Pin\">Pin</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;TransactionStatusStreamFor&lt;Self&gt;&gt;&gt;, Self::Error&gt;</h4></section></summary><div class='docblock'>Returns a future that import a single transaction and starts to watch their progress in the\npool.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ready_at\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#405-407\">source</a><a href=\"#method.ready_at\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ready_at</a>(\n    &amp;self,\n    at: NumberFor&lt;Self::Block&gt;\n) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/pin/struct.Pin.html\" title=\"struct core::pin::Pin\">Pin</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;dyn <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/future/future/trait.Future.html\" title=\"trait core::future::future::Future\">Future</a>&lt;Output = <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;dyn ReadyTransactions&lt;Item = <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;Transaction&lt;&lt;&lt;PoolApi as ChainApi&gt;::Block as BlockT&gt;::Hash, &lt;&lt;PoolApi as ChainApi&gt;::Block as BlockT&gt;::Extrinsic&gt;&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>&gt;&gt;</h4></section></summary><div class='docblock'>Get an iterator for ready transactions ordered by priority. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ready\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#409-411\">source</a><a href=\"#method.ready\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ready</a>(\n    &amp;self\n) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;dyn ReadyTransactions&lt;Item = <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;Transaction&lt;&lt;&lt;PoolApi as ChainApi&gt;::Block as BlockT&gt;::Hash, &lt;&lt;PoolApi as ChainApi&gt;::Block as BlockT&gt;::Extrinsic&gt;&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>&gt;</h4></section></summary><div class='docblock'>Get an iterator for ready transactions ordered by priority.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.remove_invalid\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#413-415\">source</a><a href=\"#method.remove_invalid\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">remove_invalid</a>(\n    &amp;self,\n    hashes: &amp;[TxHash&lt;Self&gt;]\n) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;Self::InPoolTransaction&gt;&gt;</h4></section></summary><div class='docblock'>Remove transactions identified by given hashes (and dependent transactions) from the pool.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.status\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#417-419\">source</a><a href=\"#method.status\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">status</a>(&amp;self) -&gt; PoolStatus</h4></section></summary><div class='docblock'>Returns pool status.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.futures\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#421-423\">source</a><a href=\"#method.futures\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">futures</a>(&amp;self) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;Self::InPoolTransaction&gt;</h4></section></summary><div class='docblock'>Get futures transaction list.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.import_notification_stream\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#425-427\">source</a><a href=\"#method.import_notification_stream\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">import_notification_stream</a>(&amp;self) -&gt; ImportNotificationStream&lt;TxHash&lt;Self&gt;&gt;</h4></section></summary><div class='docblock'>Return an event stream of transactions imported to the pool.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_broadcasted\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#429-431\">source</a><a href=\"#method.on_broadcasted\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_broadcasted</a>(&amp;self, propagations: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/collections/hash/map/struct.HashMap.html\" title=\"struct std::collections::hash::map::HashMap\">HashMap</a>&lt;TxHash&lt;Self&gt;, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt;&gt;)</h4></section></summary><div class='docblock'>Notify the pool about transactions broadcast.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_of\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#433-435\">source</a><a href=\"#method.hash_of\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">hash_of</a>(&amp;self, xt: &amp;TransactionFor&lt;Self&gt;) -&gt; TxHash&lt;Self&gt;</h4></section></summary><div class='docblock'>Returns transaction hash</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ready_transaction\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_service/transaction_pool.rs.html#437-439\">source</a><a href=\"#method.ready_transaction\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ready_transaction</a>(\n    &amp;self,\n    hash: &amp;TxHash&lt;Self&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;Self::InPoolTransaction&gt;&gt;</h4></section></summary><div class='docblock'>Return specific ready transaction by hash, if there is one.</div></details></div></details>","TransactionPool","subspace_service::transaction_pool::FullPool"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()