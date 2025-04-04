use codecrafters_shell::autocomplete::Trie;

fn main() {
    let mut trie = Trie::new();
    let words = [
        "herby", "bhakta", "pedros", "forcibly", "yew", "dialogs", "gypseous", "fellatio", "deys",
        "rosettes", "longs", "platinum", "truckage", "toughy", "endgames", "rest", "digits",
        "lifework", "bouquets", "hairworm", "someway", "tylosins", "outeat", "rayahs", "arillode",
        "goldarns", "protests", "chorions", "myxocyte", "hencoops", "magnate", "dangs", "hove",
        "ardent", "punitory", "xylem", "epitaxic", "ixodids", "tangler", "clozes", "harms",
        "parodic", "panderer", "area", "mukluk", "skins", "warstles", "simplify", "nelumbo",
        "rifely", "hyson", "pams", "evite", "snowbird", "aluminic", "carses", "friskers",
        "mallows", "conation", "mustees", "adroitly", "teind", "dinger", "fined", "typey",
        "glozing", "brechans", "hags", "datives", "sinuates", "bacalaos", "vocalize", "rebuked",
        "foetor", "yawned", "coos", "enisle", "outbless", "ickiness", "spouses", "picacho",
        "spahees", "bishop", "octaval", "twelve", "spieled", "feisty", "pontine", "marksman",
        "aikidos", "drupe", "castles", "seconde", "cyclicly", "missuits", "splinter", "leisures",
        "caisson", "pattypan", "podding", "futon", "pretaped", "flinched", "lumps", "policing",
        "piki", "argosies", "stench", "sintered", "culmed", "gurgle", "beamed", "concords",
        "douma", "warbles", "glutens", "standish", "tuques", "campfire", "vulvae", "bricks",
        "cattery", "daybreak", "poxing", "princess", "orangs", "debtors", "catlin", "grievers",
        "lallan", "jimjams", "bitingly", "pecans", "swimmers", "daddy", "coddler", "foxtail",
        "lug", "comfrey", "unmixed", "jarovize", "snoopy", "unwraps", "twiners", "croon",
        "softens", "rueful", "clamors", "elm", "abaters", "mycelial", "defensed", "ablings",
        "wawl", "winger", "tattler", "hoopoe", "flocci", "dug", "voteable", "tinstone", "spirited",
        "alliable", "shatters", "galere", "coaches", "ophidian", "seviche", "mirliton", "matts",
        "misroute", "mueslis", "jagras", "genre", "dandies", "mussed", "chousing", "broncs",
        "midmosts", "katchina", "undocks", "bender", "edgewise", "swagers", "inshrine", "aw",
        "efs", "twister", "enfeoff", "tumour", "flambeau", "blowby", "flatcars", "barongs", "naos",
        "misadd", "prosers", "virile", "dutiable", "farthing", "stound", "hellbox", "piped",
        "cruset", "firmly", "trusteed", "praelect", "trekked", "retailed", "nullahs", "powers",
        "coerces", "legate", "cofounds", "reseau", "shlepps", "antres", "sadder", "ax", "enscroll",
        "oxidise", "chuck", "devil", "subline", "oars", "farcies", "piddler", "devils", "dopier",
        "totaled", "motley", "tearily", "molybdic", "collages", "scalages", "claybank", "weeding",
        "poller", "rookies", "vinyl", "overing", "orbed", "zonking", "reearn", "hairnet", "impis",
        "shore", "quizzer", "beige", "chocking", "upstood", "mistrial", "airfield", "gaun",
        "prints", "craws", "replots", "blink", "crapes", "clinging", "strum", "outfeast",
        "versant", "faquir", "zooecium", "towering", "feirie", "bouldery", "vrooming", "hawker",
        "underjaw", "septaria", "cultches", "roundup", "spas", "pouted", "paresis", "retitled",
        "holms", "tasked", "trunked", "holdup", "jowly", "eloigns", "unlawful", "barehead",
        "bobcat", "lierne", "orang", "leisters", "pussly", "rissole", "deleaved", "suberins",
        "barmier", "starkest", "husband", "chital", "venial", "dishiest", "copens", "spader",
        "strafers", "milo", "roping", "gauffer", "lippiest", "darkie", "denes", "learns",
        "unamused", "crumb", "jipijapa", "genteel", "tomentum", "handbell", "cullay", "muscling",
        "vairs", "oldwife", "nontoxic", "leaves", "shrewed", "rhythm", "kaffiyeh", "camorra",
        "bola", "goggled", "wanders", "bunkums", "miquelet", "scullion", "cerate", "autopsic",
        "dowering", "bogyman", "veery", "reffing", "medicaid", "infringe", "dodo", "gullies",
        "jews", "spotter", "workable", "jeweled", "arfs", "flooder", "artworks", "saccules",
        "alleys", "hansa", "stealing", "strove", "ogress", "ecru", "speckle", "dammer", "pouts",
        "booklet", "windage", "renewer", "mumble", "klavern", "gutty", "adage", "syboes",
        "savarins", "summers", "slugfest", "axillar", "tectites", "wienies", "inertiae", "collins",
        "fistulae", "shadblow", "unwishes", "prowls", "pooched", "pressmen", "fumigant",
        "absonant", "gox", "caves", "wilful", "revetted", "pungent", "fainted", "roles", "studies",
        "racemous", "trippet", "spence", "coifs", "lows", "waggle", "dilute", "trackway",
        "deodara", "tokonoma", "shittah", "heel", "speculum", "fossae", "clans", "contrail",
        "keckle", "reacted", "demerits", "mesas", "dhoti", "tympany", "locater", "anchored",
        "glumpier", "faddisms", "creped", "dozened", "quest", "bowses", "poetises", "grater",
        "parle", "keblah", "pervades", "mockery", "prey", "adamance", "squarer", "trice",
        "pelicans", "biding", "automan", "mounted", "kiboshed", "tiller", "refits", "spake",
        "rebuker", "oestrone", "robalos", "suss", "labiate", "slang", "abys", "embalmed",
        "nodally", "poleward", "drawers", "tattered", "tining", "familiar", "sport", "emblazes",
        "deadpans", "coaxial", "mediocre", "wariness", "babkas", "effusive", "prides", "baizes",
        "wadmaal", "honoring", "overeasy", "unwrap", "galletas", "couloir", "pitting", "kine",
        "hugeness", "ballad", "rumoring", "primness", "probing", "seer", "gnomes", "sharif",
        "laryngal", "invokes", "florae", "metrists", "untuck", "hoops", "ileac", "outbuilt",
        "retold", "ablation", "unduly", "spaded", "paddy", "retints", "plimsol", "facias",
        "tertials", "mothered", "verser", "ariose", "drouths", "ratos", "desulfur", "logway",
        "join", "heehaw", "cutes", "blurbing", "ebb", "tupped", "spooks", "apyretic", "seaters",
        "syzygy", "assenter", "perineal", "snubbed", "priseres", "landing", "foul", "northers",
        "extinct", "atamasco", "abulia", "recorded", "holly", "hails", "reweaves", "heirship",
        "nimbused", "diseuses", "misusers", "narcos", "tour", "chirre", "gamays", "remotes",
        "vetoing", "lingers", "quisling", "noteless", "thionin", "agone", "jut", "philtred",
        "prefab", "avaunt", "moonbeam", "wataps", "swotted", "batten", "pavior", "maleates",
        "farmable", "natures", "staples", "laths", "runty", "ungraced", "muddles", "veneerer",
        "cornutos", "baited", "ceiled", "yakking", "coopered", "patzer", "outslick", "kief",
        "irater", "ulamas", "whipping", "wiredrew", "weirdest", "composer", "iritis", "itching",
        "scalades", "carmaker", "gluttons", "stagnant", "gullet", "peatiest", "hooflike",
        "loculed", "airplays", "doze", "dining", "doffer", "repeated", "globes", "uranisms",
        "someones", "amitosis", "calf", "unbenign", "epicalyx", "shent", "ciphony", "spiled",
        "anionic", "lousier", "durums", "twangler", "japery", "shorans", "gooiest", "outblaze",
        "dagga", "inform", "dobby", "swankest", "melodist", "nurtures", "stourie", "toponymy",
        "rhea", "fuller", "soulless", "feoffer", "inborn", "cowhages", "ruff", "souse", "caries",
        "frow", "attacks", "cutlers", "nervines", "tenebrae", "somas", "dioxid", "subduce",
        "beadles", "fucose", "monodic", "wailers", "exertion", "gardener", "footling", "adsorb",
        "boot", "grovels", "folioing", "rockabye", "knaps", "seedy", "etuis", "reprint",
        "dispatch", "communed", "shipside", "trews", "wideness", "marvel", "recapped", "colorer",
        "loins", "naysayer", "tun", "octavo", "cottons", "builds", "semifit", "progged", "dust",
        "gracious", "spaller", "nonfacts", "reined", "soirees", "abstains", "pianos", "steeled",
        "loathe", "dysurias", "col", "dukedom", "camisas", "rulable", "lidars", "kishkas",
        "upgirded", "evanesce", "greets", "giddied", "smoking", "rootlet", "vacuums", "fetchers",
        "yeastier", "mouthily", "user", "catholic", "couples", "disusing", "unsteady", "fireclay",
        "putoff", "mouflon", "em", "hello", "vulgo", "helos", "spondaic", "ponds", "genros",
        "paramos", "garbling", "flamens", "cooingly", "leg", "gore", "pneumas", "unhat", "obtunds",
        "pyrans", "fiches", "opossum", "flexuous", "thew", "miscut", "beflecks", "poops",
        "conclude", "lander", "refugium", "mostests", "plunked", "bedlike", "apollo", "handrail",
        "dais", "subduers", "syntony", "rearms", "wagoner", "steeps", "comtes", "relate", "randy",
        "cannoned", "ariled", "refiling", "boners", "zygoid", "subsumes", "maggot", "debrief",
        "meatily", "zaribas", "gazogene", "stilt", "unafraid", "kyanise", "balatas", "elastins",
        "wildness", "lunet", "nilled", "slaw", "plethora", "keelless", "naganas", "overlent",
        "resorted", "rolfed", "burl", "bighted", "lipped", "doeskins", "stelene", "whooping",
        "alation", "parodoi", "desalt", "couple", "mining", "tarns", "hipless", "humming",
        "ambroid", "forepaws", "halachot", "missed", "kiltings", "obligato", "doctor", "slitters",
        "combed", "antonym", "rebecks", "outrates", "outfeels", "wristy", "slavey", "varmints",
        "quillets", "baryte", "taenias", "sherbets", "outspan", "purplish", "gelable", "hangnail",
        "hodaddy", "fluorid", "bionts", "homing", "melling", "daftness", "nuptial", "skoal",
        "disbands", "polemize", "afrit", "sands", "metaled", "beseem", "betoken", "misfired",
        "lessee", "missends", "scatters", "spookier", "incult", "ploying", "camshaft", "mintages",
        "storage", "jointed", "rubrical", "illest", "proses", "moneyers", "misdoes", "direst",
        "embosses", "ghastful", "ocker", "crofter", "betise", "sendal", "psywars", "blear",
        "cunning", "walkable", "axilla", "lambies", "awaked", "toters", "doters", "gasalier",
        "patly", "cabinets", "tangles", "exergues", "luthier", "forty", "absently", "tibiae",
        "hocusses", "tuts", "haded", "atwitter", "prismoid", "leases", "futz", "alegars",
        "glutting", "bioplasm", "pipped", "chamfron", "easterly", "grocer", "dine", "kyak",
        "scoopful", "sora", "plimsole", "antes", "widgeons", "parados", "comakers", "netts",
        "derrick", "pile", "futures", "aleuron", "rato", "lances", "island", "nymphs", "tabanid",
        "jettison", "twangy", "hunting", "drillers", "tamable", "tankards", "redid", "phytol",
        "quaichs", "bulbuls", "stinkard", "nobodies", "tattoo", "pyxidia", "branches", "shojis",
        "spinless", "infolds", "redrill", "thesauri", "telluric", "lovat", "relined", "silklike",
        "redbaits", "tactics", "waiters", "mihrab", "swanpans", "palmyra", "pedaled", "otiosely",
        "paltered", "verniers", "hambones", "doyenne", "mongered", "saltwort", "caroche",
        "ticking", "cresylic", "paravane", "dementia", "wellborn", "padauk", "cuscuses",
        "abeyancy", "taborets", "shocks", "restrike", "freeload", "orgone", "tegumina", "taco",
        "elegized", "jalopies", "polo", "brocks", "nonfan", "apposing", "snivels", "coarsens",
        "clocks", "ditherer", "stogies", "bleared", "quainter", "motifs", "hances", "cloques",
        "sploshed", "deftness", "perique", "thymier", "bedcover", "zax", "wairing", "shophars",
        "mache", "gayer", "repowers", "write", "dealer", "hetaeras", "mauds", "fictive", "seriema",
        "cocoyam", "doilies", "dispend", "intrados", "births", "erectors", "raked", "enjoiner",
        "vamoses", "gruffly", "showring", "redates", "briards", "serviced", "credenda", "cee",
        "gills", "booths", "shoat", "escheat",
    ];

    trie.extend(words);

    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input == "\n" {
            break;
        }

        dbg!(trie.suggest(&input[..input.len() - 1]));
    }
}
