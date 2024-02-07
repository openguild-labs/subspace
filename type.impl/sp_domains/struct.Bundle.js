(function() {var type_impls = {
"sp_domains":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#323-379\">source</a><a href=\"#impl-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic: Encode, Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode&gt; <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#327-329\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.hash\" class=\"fn\">hash</a>(&amp;self) -&gt; H256</h4></section></summary><div class=\"docblock\"><p>Returns the hash of this bundle.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.domain_id\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#332-334\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.domain_id\" class=\"fn\">domain_id</a>(&amp;self) -&gt; <a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a></h4></section></summary><div class=\"docblock\"><p>Returns the domain_id of this bundle.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.extrinsics_root\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#337-339\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.extrinsics_root\" class=\"fn\">extrinsics_root</a>(&amp;self) -&gt; <a class=\"type\" href=\"sp_domains/type.HeaderHashFor.html\" title=\"type sp_domains::HeaderHashFor\">HeaderHashFor</a>&lt;DomainHeader&gt;</h4></section></summary><div class=\"docblock\"><p>Return the <code>bundle_extrinsics_root</code></p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.operator_id\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#342-344\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.operator_id\" class=\"fn\">operator_id</a>(&amp;self) -&gt; <a class=\"type\" href=\"sp_domains/type.OperatorId.html\" title=\"type sp_domains::OperatorId\">OperatorId</a></h4></section></summary><div class=\"docblock\"><p>Return the <code>operator_id</code></p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.receipt\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#347-357\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.receipt\" class=\"fn\">receipt</a>(\n    &amp;self\n) -&gt; &amp;<a class=\"struct\" href=\"sp_domains/struct.ExecutionReceipt.html\" title=\"struct sp_domains::ExecutionReceipt\">ExecutionReceipt</a>&lt;Number, Hash, <a class=\"type\" href=\"sp_domains/type.HeaderNumberFor.html\" title=\"type sp_domains::HeaderNumberFor\">HeaderNumberFor</a>&lt;DomainHeader&gt;, <a class=\"type\" href=\"sp_domains/type.HeaderHashFor.html\" title=\"type sp_domains::HeaderHashFor\">HeaderHashFor</a>&lt;DomainHeader&gt;, Balance&gt;</h4></section></summary><div class=\"docblock\"><p>Return a reference of the execution receipt.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.into_receipt\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#360-370\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.into_receipt\" class=\"fn\">into_receipt</a>(\n    self\n) -&gt; <a class=\"struct\" href=\"sp_domains/struct.ExecutionReceipt.html\" title=\"struct sp_domains::ExecutionReceipt\">ExecutionReceipt</a>&lt;Number, Hash, <a class=\"type\" href=\"sp_domains/type.HeaderNumberFor.html\" title=\"type sp_domains::HeaderNumberFor\">HeaderNumberFor</a>&lt;DomainHeader&gt;, <a class=\"type\" href=\"sp_domains/type.HeaderHashFor.html\" title=\"type sp_domains::HeaderHashFor\">HeaderHashFor</a>&lt;DomainHeader&gt;, Balance&gt;</h4></section></summary><div class=\"docblock\"><p>Consumes <a href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\"><code>Bundle</code></a> to extract the execution receipt.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.size\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#373-378\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.size\" class=\"fn\">size</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h4></section></summary><div class=\"docblock\"><p>Return the bundle body size in bytes</p>\n</div></details></div></details>",0,"sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#389-410\">source</a><a href=\"#impl-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic: Encode, Number, Hash, DomainHeader: HeaderT, Balance&gt; <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.into_opaque_bundle\" class=\"method\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#393-409\">source</a><h4 class=\"code-header\">pub fn <a href=\"sp_domains/struct.Bundle.html#tymethod.into_opaque_bundle\" class=\"fn\">into_opaque_bundle</a>(\n    self\n) -&gt; <a class=\"type\" href=\"sp_domains/type.OpaqueBundle.html\" title=\"type sp_domains::OpaqueBundle\">OpaqueBundle</a>&lt;Number, Hash, DomainHeader, Balance&gt;</h4></section></summary><div class=\"docblock\"><p>Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.</p>\n</div></details></div></details>",0,"sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-PartialEq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>, Number: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>, Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>, DomainHeader: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> + HeaderT, Balance: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(\n    &amp;self,\n    other: &amp;<a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;\n) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-Clone-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, Number: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, DomainHeader: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + HeaderT, Balance: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","sp_domains::OpaqueBundle"],["<section id=\"impl-StructuralEq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-StructuralEq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralEq.html\" title=\"trait core::marker::StructuralEq\">StructuralEq</a> for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section>","StructuralEq","sp_domains::OpaqueBundle"],["<section id=\"impl-Eq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-Eq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, Number: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, DomainHeader: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + HeaderT, Balance: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section>","Eq","sp_domains::OpaqueBundle"],["<section id=\"impl-StructuralPartialEq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-StructuralPartialEq-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section>","StructuralPartialEq","sp_domains::OpaqueBundle"],["<section id=\"impl-EncodeLike-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-EncodeLike-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance&gt; EncodeLike for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;<div class=\"where\">where\n    <a class=\"struct\" href=\"sp_domains/struct.SealedBundleHeader.html\" title=\"struct sp_domains::SealedBundleHeader\">SealedBundleHeader</a>&lt;Number, Hash, DomainHeader, Balance&gt;: Encode,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;Extrinsic&gt;: Encode,</div></h3></section>","EncodeLike","sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-Debug-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>, Number: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>, Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>, DomainHeader: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + HeaderT, Balance: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Decode-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-Decode-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance&gt; Decode for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;<div class=\"where\">where\n    <a class=\"struct\" href=\"sp_domains/struct.SealedBundleHeader.html\" title=\"struct sp_domains::SealedBundleHeader\">SealedBundleHeader</a>&lt;Number, Hash, DomainHeader, Balance&gt;: Decode,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;Extrinsic&gt;: Decode,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.decode\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.decode\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">decode</a>&lt;__CodecInputEdqy: Input&gt;(\n    __codec_input_edqy: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut __CodecInputEdqy</a>\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, Error&gt;</h4></section></summary><div class='docblock'>Attempt to deserialise the value from input.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.decode_into\" class=\"method trait-impl\"><a href=\"#method.decode_into\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">decode_into</a>&lt;I&gt;(\n    input: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut I</a>,\n    dst: &amp;mut <a class=\"union\" href=\"https://doc.rust-lang.org/nightly/core/mem/maybe_uninit/union.MaybeUninit.html\" title=\"union core::mem::maybe_uninit::MaybeUninit\">MaybeUninit</a>&lt;Self&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;DecodeFinished, Error&gt;<div class=\"where\">where\n    I: Input,</div></h4></section></summary><div class='docblock'>Attempt to deserialize the value from input into a pre-allocated piece of memory. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.skip\" class=\"method trait-impl\"><a href=\"#method.skip\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">skip</a>&lt;I&gt;(input: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut I</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, Error&gt;<div class=\"where\">where\n    I: Input,</div></h4></section></summary><div class='docblock'>Attempt to skip the encoded value from input. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encoded_fixed_size\" class=\"method trait-impl\"><a href=\"#method.encoded_fixed_size\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">encoded_fixed_size</a>() -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt;</h4></section></summary><div class='docblock'>Returns the fixed encoded size of the type. <a>Read more</a></div></details></div></details>","Decode","sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Encode-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-Encode-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance&gt; Encode for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;<div class=\"where\">where\n    <a class=\"struct\" href=\"sp_domains/struct.SealedBundleHeader.html\" title=\"struct sp_domains::SealedBundleHeader\">SealedBundleHeader</a>&lt;Number, Hash, DomainHeader, Balance&gt;: Encode,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;Extrinsic&gt;: Encode,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.size_hint\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.size_hint\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">size_hint</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>If possible give a hint of expected size of the encoding. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encode_to\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.encode_to\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">encode_to</a>&lt;__CodecOutputEdqy: Output + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt;(\n    &amp;self,\n    __codec_dest_edqy: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut __CodecOutputEdqy</a>\n)</h4></section></summary><div class='docblock'>Convert self to a slice and append it to the destination.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encode\" class=\"method trait-impl\"><a href=\"#method.encode\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">encode</a>(&amp;self) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; <a href=\"#\" class=\"tooltip\" data-notable-ty=\"Vec&lt;u8&gt;\">ⓘ</a></h4></section></summary><div class='docblock'>Convert self to an owned vector.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.using_encoded\" class=\"method trait-impl\"><a href=\"#method.using_encoded\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">using_encoded</a>&lt;R, F&gt;(&amp;self, f: F) -&gt; R<div class=\"where\">where\n    F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/function/trait.FnOnce.html\" title=\"trait core::ops::function::FnOnce\">FnOnce</a>(&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>]) -&gt; R,</div></h4></section></summary><div class='docblock'>Convert self to a slice and then invoke the given closure with it.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encoded_size\" class=\"method trait-impl\"><a href=\"#method.encoded_size\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">encoded_size</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>Calculates the encoded size. <a>Read more</a></div></details></div></details>","Encode","sp_domains::OpaqueBundle"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TypeInfo-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#impl-TypeInfo-for-Bundle%3CExtrinsic,+Number,+Hash,+DomainHeader,+Balance%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt; TypeInfo for <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;<div class=\"where\">where\n    <a class=\"struct\" href=\"sp_domains/struct.SealedBundleHeader.html\" title=\"struct sp_domains::SealedBundleHeader\">SealedBundleHeader</a>&lt;Number, Hash, DomainHeader, Balance&gt;: TypeInfo + 'static,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;Extrinsic&gt;: TypeInfo + 'static,\n    Extrinsic: TypeInfo + 'static,\n    Number: TypeInfo + 'static,\n    Hash: TypeInfo + 'static,\n    DomainHeader: HeaderT + TypeInfo + 'static,\n    Balance: TypeInfo + 'static,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Identity\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Identity\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Identity</a> = <a class=\"struct\" href=\"sp_domains/struct.Bundle.html\" title=\"struct sp_domains::Bundle\">Bundle</a>&lt;Extrinsic, Number, Hash, DomainHeader, Balance&gt;</h4></section></summary><div class='docblock'>The type identifying for which type info is provided. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.type_info\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#315\">source</a><a href=\"#method.type_info\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">type_info</a>() -&gt; Type</h4></section></summary><div class='docblock'>Returns the static type identifier for <code>Self</code>.</div></details></div></details>","TypeInfo","sp_domains::OpaqueBundle"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()